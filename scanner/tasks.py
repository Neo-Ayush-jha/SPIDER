import os
import subprocess
import sys
import xml.etree.ElementTree as ET

from celery import shared_task
from django.utils import timezone

from .models import ScanResult, ScanTask
from .security import analyze_scan_results


@shared_task(bind=True)
def run_scan(self, scan_id):
    try:
        scan = ScanTask.objects.get(pk=scan_id)
    except ScanTask.DoesNotExist:
        return {'error': 'scan not found'}

    scan.status = 'RUNNING'
    scan.start_time = timezone.now()
    scan.save(update_fields=['status', 'start_time'])

    target = scan.target
    ports = scan.port_range

    nmap_path = r"C:\Program Files (x86)\Nmap\nmap.exe"
    if not os.path.exists(nmap_path):
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save(update_fields=['status', 'end_time'])
        return {'error': f'nmap not found at {nmap_path}'}

    scan_type = '-sT'
    if sys.platform.startswith('win'):
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
            if is_admin:
                scan_type = '-sS'
        except Exception:
            pass

    command = [nmap_path, scan_type, '-Pn', '-sV', '--version-light', '-p', ports, '-oX', '-', target]

    try:
        xml_out = subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as exc:
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save(update_fields=['status', 'end_time'])
        return {'error': 'nmap scan failed', 'details': exc.output}
    except Exception as exc:
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save(update_fields=['status', 'end_time'])
        return {'error': 'unexpected error', 'details': str(exc)}

    created_rows = []
    try:
        root = ET.fromstring(xml_out)
        for host in root.findall('host'):
            for ports_el in host.findall('ports'):
                for port_el in ports_el.findall('port'):
                    portid = int(port_el.get('portid'))
                    state_el = port_el.find('state')
                    state = state_el.get('state') if state_el is not None else 'unknown'
                    reason = state_el.get('reason') if state_el is not None else ''
                    ttl = state_el.get('reason_ttl') if state_el is not None else ''
                    service_el = port_el.find('service')
                    service = service_el.get('name') if service_el is not None else ''

                    if state in ['open', 'filtered', 'closed']:
                        ScanResult.objects.create(
                            scan=scan,
                            port=portid,
                            state=state,
                            service=service,
                            reason=reason,
                            ttl=ttl,
                        )
                        created_rows.append({'port': portid, 'state': state, 'service': service})
    except ET.ParseError as exc:
        scan.status = 'FAILED'
        scan.end_time = timezone.now()
        scan.save(update_fields=['status', 'end_time'])
        return {'error': 'failed to parse nmap XML', 'details': str(exc)}

    summary, _ = analyze_scan_results(created_rows)
    scan.status = 'COMPLETED'
    scan.end_time = timezone.now()
    scan.risk_score = summary['risk_score']
    scan.save(update_fields=['status', 'end_time', 'risk_score'])
    return {'status': 'completed', 'scan_id': scan_id, 'risk_score': scan.risk_score}
