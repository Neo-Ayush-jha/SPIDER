import csv
import json
import uuid

import razorpay
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User
from django.http import Http404, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_exempt

from .models import PaymentRecord, ScanTask, UserProfile
from .ai_explainer import explain_open_port, explain_vulnerability
from .security import SCAN_PRESETS, analyze_scan_results, normalize_port_input, resolve_target, sanitize_target
from .tasks import run_scan


def index(request):
    return render(request, 'scanner/index.html', {'scan_presets': SCAN_PRESETS})


def home(request):
    recent_scans = []
    if request.user.is_authenticated:
        recent_scans = ScanTask.objects.filter(user=request.user).order_by('-created_at')[:5]
    return render(request, 'scanner/home.html', {'recent_scans': recent_scans, 'scan_presets': SCAN_PRESETS})


@login_required
def scan_history(request):
    scans = ScanTask.objects.filter(user=request.user).order_by('-created_at')[:25]
    return render(request, 'scanner/history.html', {'scans': scans})


@login_required
def scan_detail(request, scan_id):
    scan = _scan_or_404(scan_id, request.user)
    results = list(scan.scanresult_set.values('port', 'state', 'service'))
    summary, findings = analyze_scan_results(results)
    _attach_ai_explanations(scan, results, findings)

    context = {
        'scan': scan,
        'summary': summary,
        'findings': findings[:8],
        'results': results,
    }
    return render(request, 'scanner/scan_detail.html', context)


def _scan_or_404(scan_id, user):
    scan = get_object_or_404(ScanTask, pk=scan_id)
    if scan.user_id and scan.user_id != user.id and not user.is_staff:
        raise Http404('Scan not found.')
    return scan


def _attach_ai_explanations(scan, results, findings):
    if scan.status != 'COMPLETED':
        return

    for result in results:
        if (result.get('state') or '').lower() != 'open':
            continue
        detail, provider = explain_open_port(
            int(result.get('port') or 0),
            result.get('service', ''),
            result.get('state', ''),
        )
        result['ai_detail'] = detail
        result['ai_provider'] = provider

    for finding in findings:
        detail, provider = explain_vulnerability(
            finding.get('title', ''),
            finding.get('category', ''),
            int(finding.get('port') or 0),
            finding.get('recommendation', ''),
        )
        finding['ai_detail'] = detail
        finding['ai_provider'] = provider


@login_required
def start_scan(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST only'}, status=405)

    try:
        data = json.loads(request.body.decode('utf-8'))
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Invalid JSON payload.'}, status=400)

    target_input = data.get('target')
    requested_ports = data.get('ports', '1-1024')
    scan_profile = data.get('profile', 'custom')

    try:
        requested_target, normalized_target = sanitize_target(target_input)
        ports = normalize_port_input(requested_ports)
    except ValueError as exc:
        return JsonResponse({'error': str(exc)}, status=400)

    if scan_profile not in SCAN_PRESETS:
        scan_profile = 'custom'

    target_ip = resolve_target(normalized_target)
    if not target_ip:
        return JsonResponse({'error': 'Invalid domain or IP. Unable to resolve target.'}, status=400)

    profile, _ = UserProfile.objects.get_or_create(user=request.user)

    unique_task = str(uuid.uuid4())
    scan = ScanTask.objects.create(
        user=request.user,
        task_id=unique_task,
        requested_target=requested_target,
        target=target_ip,
        port_range=ports,
        scan_profile=scan_profile,
        status='PENDING',
    )

    async_result = run_scan.delay(scan.id)
    profile.scan_count += 1
    profile.save(update_fields=['scan_count'])

    return JsonResponse({
        'scan_db_id': scan.id,
        'task_uuid': unique_task,
        'celery_id': async_result.id,
        'resolved_target': target_ip,
        'profile': scan_profile,
        'ports': ports,
    })


@login_required
def scan_status(request, scan_id):
    scan = _scan_or_404(scan_id, request.user)
    results = list(scan.scanresult_set.values('port', 'state', 'service'))
    summary, findings = analyze_scan_results(results)
    _attach_ai_explanations(scan, results, findings)

    if scan.risk_score != summary['risk_score']:
        scan.risk_score = summary['risk_score']
        scan.save(update_fields=['risk_score'])

    return JsonResponse({
        'scan_db_id': scan.id,
        'target': scan.target,
        'requested_target': scan.requested_target or scan.target,
        'status': scan.status,
        'profile': scan.scan_profile,
        'port_range': scan.port_range,
        'risk_score': scan.risk_score,
        'results': results,
        'summary': summary,
        'findings': findings[:8],
        'start_time': scan.start_time.isoformat() if scan.start_time else None,
        'end_time': scan.end_time.isoformat() if scan.end_time else None,
    })


@login_required
def export_csv(request, scan_id):
    scan = _scan_or_404(scan_id, request.user)
    results = list(scan.scanresult_set.values('port', 'state', 'service'))
    summary, findings = analyze_scan_results(results)
    _attach_ai_explanations(scan, results, findings)

    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}.csv"'

    writer = csv.writer(response)
    writer.writerow(['requested_target', scan.requested_target or scan.target])
    writer.writerow(['resolved_target', scan.target])
    writer.writerow(['scan_profile', scan.scan_profile])
    writer.writerow(['port_range', scan.port_range])
    writer.writerow(['risk_score', summary['risk_score']])
    writer.writerow([])
    writer.writerow(['port', 'name', 'state', 'service', 'risk_level', 'category', 'description', 'usage', 'ai_provider', 'ai_detail'])

    for row in results:
        writer.writerow([
            row['port'],
            row['name'],
            row['state'],
            row.get('service', ''),
            row['risk_level'],
            row['category'],
            row['description'],
            row['usage'],
            row.get('ai_provider', ''),
            row.get('ai_detail', ''),
        ])

    return response


@login_required
def export_json(request, scan_id):
    scan = _scan_or_404(scan_id, request.user)
    results = list(scan.scanresult_set.values('port', 'state', 'service'))
    summary, findings = analyze_scan_results(results)
    _attach_ai_explanations(scan, results, findings)
    payload = {
        'scan_id': scan.id,
        'requested_target': scan.requested_target or scan.target,
        'resolved_target': scan.target,
        'profile': scan.scan_profile,
        'port_range': scan.port_range,
        'status': scan.status,
        'summary': summary,
        'findings': findings[:8],
        'results': results,
        'start_time': scan.start_time.isoformat() if scan.start_time else None,
        'end_time': scan.end_time.isoformat() if scan.end_time else None,
    }
    response = HttpResponse(json.dumps(payload, indent=2), content_type='application/json')
    response['Content-Disposition'] = f'attachment; filename="scan_{scan_id}.json"'
    return response


def register_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        email = request.POST.get('email')
        password = request.POST.get('password')

        if not username or not password:
            messages.error(request, 'Username and password required.')
            return redirect('register')

        if User.objects.filter(username=username).exists():
            messages.error(request, 'Username already taken.')
            return redirect('register')

        user = User.objects.create_user(username=username, email=email, password=password)
        user.save()

        messages.success(request, 'Registration successful. Please login.')
        return redirect('login')

    return render(request, 'scanner/register.html')



def login_user(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            return redirect('home')
        messages.error(request, 'Invalid credentials.')
        return redirect('login')
    return render(request, 'scanner/login.html')


def logout_user(request):
    logout(request)
    return redirect('home')


@login_required
def make_payment(request):
    client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_SECRET))
    amount_rupees = 49
    amount_paise = int(amount_rupees * 100)
    razor_order = client.order.create({'amount': amount_paise, 'currency': 'INR', 'payment_capture': 1})
    PaymentRecord.objects.create(user=request.user, razorpay_order_id=razor_order['id'], amount=amount_rupees)
    context = {
        'order': razor_order,
        'key_id': settings.RAZORPAY_KEY_ID,
        'amount': amount_paise,
    }
    return render(request, 'scanner/make_payment.html', context)


@csrf_exempt
def verify_payment(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'POST required'}, status=405)
    try:
        data = json.loads(request.body.decode('utf-8'))
        razorpay_order_id = data.get('razorpay_order_id')
        razorpay_payment_id = data.get('razorpay_payment_id')
        razorpay_signature = data.get('razorpay_signature')

        client = razorpay.Client(auth=(settings.RAZORPAY_KEY_ID, settings.RAZORPAY_SECRET))
        params = {
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature,
        }
        try:
            client.utility.verify_payment_signature(params)
        except razorpay.errors.SignatureVerificationError:
            return JsonResponse({'status': 'failed', 'reason': 'signature_invalid'}, status=400)

        payment = PaymentRecord.objects.filter(razorpay_order_id=razorpay_order_id).first()
        if not payment:
            return JsonResponse({'status': 'failed', 'reason': 'order_not_found'}, status=404)

        payment.razorpay_payment_id = razorpay_payment_id
        payment.razorpay_signature = razorpay_signature
        payment.status = 'SUCCESS'
        payment.save()

        profile = UserProfile.objects.get(user=payment.user)
        profile.has_paid = True
        profile.scan_count = 0
        profile.save(update_fields=['has_paid', 'scan_count'])

        return JsonResponse({'status': 'success'})
    except Exception as exc:
        return JsonResponse({'status': 'error', 'error': str(exc)}, status=500)


