from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from .models import ScanResult, ScanTask
from .security import analyze_scan_results, normalize_port_input, sanitize_target


class SecurityHelpersTest(TestCase):
    def test_sanitize_target_strips_scheme_and_path(self):
        requested, normalized = sanitize_target('https://example.com/admin/login')
        self.assertEqual(requested, 'https://example.com/admin/login')
        self.assertEqual(normalized, 'example.com')

    def test_normalize_port_input_rejects_invalid_port(self):
        with self.assertRaises(ValueError):
            normalize_port_input('22,70000')

    def test_analyze_scan_results_builds_risk_summary(self):
        summary, findings = analyze_scan_results([
            {'port': 23, 'state': 'open', 'service': 'telnet'},
            {'port': 80, 'state': 'open', 'service': 'http'},
            {'port': 443, 'state': 'closed', 'service': 'https'},
        ])
        self.assertGreaterEqual(summary['risk_score'], 40)
        self.assertEqual(summary['high_risk_ports'], 2)
        self.assertTrue(any('HTTP is exposed without HTTPS' == finding['title'] for finding in findings))


class ScanViewSecurityTest(TestCase):
    def setUp(self):
        self.owner = User.objects.create_user(username='owner', password='pass12345')
        self.other_user = User.objects.create_user(username='other', password='pass12345')
        self.scan = ScanTask.objects.create(
            user=self.owner,
            task_id='scan-1',
            requested_target='example.com',
            target='93.184.216.34',
            port_range='22,80,443',
            scan_profile='web',
            status='COMPLETED',
            risk_score=55,
        )
        ScanResult.objects.create(scan=self.scan, port=22, state='open', service='ssh')
        ScanResult.objects.create(scan=self.scan, port=80, state='open', service='http')

    def test_status_requires_owner(self):
        self.client.login(username='other', password='pass12345')
        response = self.client.get(reverse('scan_status', args=[self.scan.id]))
        self.assertEqual(response.status_code, 404)

    def test_owner_can_export_json(self):
        self.client.login(username='owner', password='pass12345')
        response = self.client.get(reverse('export_json', args=[self.scan.id]))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')
        self.assertIn('requested_target', response.content.decode())

    def test_owner_can_open_scan_detail_page(self):
        self.client.login(username='owner', password='pass12345')
        response = self.client.get(reverse('scan_detail', args=[self.scan.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'Detailed Report')

    def test_non_owner_cannot_open_scan_detail_page(self):
        self.client.login(username='other', password='pass12345')
        response = self.client.get(reverse('scan_detail', args=[self.scan.id]))
        self.assertEqual(response.status_code, 404)

    @patch('scanner.views.resolve_target', return_value='93.184.216.34')
    @patch('scanner.views.run_scan.delay')
    def test_start_scan_saves_user_and_profile(self, mocked_delay, mocked_resolve):
        mocked_delay.return_value.id = 'celery-123'
        self.client.login(username='owner', password='pass12345')
        response = self.client.post(
            reverse('start_scan'),
            data='{"target": "example.com", "ports": "80,443", "profile": "web"}',
            content_type='application/json',
        )
        self.assertEqual(response.status_code, 200)
        created_scan = ScanTask.objects.exclude(id=self.scan.id).latest('id')
        self.assertEqual(created_scan.user, self.owner)
        self.assertEqual(created_scan.scan_profile, 'web')
        self.assertEqual(created_scan.port_range, '80,443')
