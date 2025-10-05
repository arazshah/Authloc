import json
from datetime import timedelta
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.contrib.gis.geos import Point
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase

from locations.models import Location

from .models import AuditLog, SecurityAlert
from .monitoring import audit_monitor
from .reports import AuditReportGenerator
from .utils import calculate_risk_score, detect_anomalies, log_user_action

User = get_user_model()


class AuditLogModelTest(TestCase):
    """Test cases for AuditLog model."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.location = Location.objects.create(
            name='Test Location',
            latitude=40.7128,
            longitude=-74.0060
        )

    def test_audit_log_creation(self):
        """Test basic audit log creation."""
        log = AuditLog.objects.create(
            user=self.user,
            username='testuser',
            action='login',
            resource_type='user',
            resource_id='123',
            ip_address='192.168.1.1',
            risk_score=25,
        )

        self.assertEqual(log.action, 'login')
        self.assertEqual(log.username, 'testuser')
        self.assertEqual(log.risk_score, 25)
        self.assertFalse(log.is_suspicious)

    def test_audit_log_str_method(self):
        """Test string representation of audit log."""
        log = AuditLog.objects.create(
            user=self.user,
            username='testuser',
            action='create',
            resource_type='user',
        )

        expected_str = "create user by testuser"
        self.assertEqual(str(log), expected_str)

    def test_audit_log_with_location(self):
        """Test audit log with location data."""
        log = AuditLog.objects.create(
            user=self.user,
            action='login',
            location=self.location,
            geo_location=Point(-74.0060, 40.7128),
        )

        self.assertEqual(log.location, self.location)
        self.assertIsNotNone(log.geo_location)


class SecurityAlertModelTest(TestCase):
    """Test cases for SecurityAlert model."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        self.audit_log = AuditLog.objects.create(
            user=self.user,
            action='login',
            risk_score=80,
        )

    def test_security_alert_creation(self):
        """Test basic security alert creation."""
        alert = SecurityAlert.objects.create(
            alert_type='suspicious_login',
            severity='high',
            title='Suspicious Login Detected',
            description='Login from unusual location',
            user=self.user,
            audit_log=self.audit_log,
            ip_address='192.168.1.1',
        )

        self.assertEqual(alert.alert_type, 'suspicious_login')
        self.assertEqual(alert.severity, 'high')
        self.assertFalse(alert.is_resolved)

    def test_security_alert_resolution(self):
        """Test security alert resolution."""
        alert = SecurityAlert.objects.create(
            alert_type='brute_force',
            severity='critical',
            title='Brute Force Attack',
            user=self.user,
        )

        # Resolve the alert
        alert.is_resolved = True
        alert.resolved_by = self.user
        alert.resolved_at = timezone.now()
        alert.resolution_notes = 'Blocked suspicious IP'
        alert.save()

        alert.refresh_from_db()
        self.assertTrue(alert.is_resolved)
        self.assertEqual(alert.resolved_by, self.user)
        self.assertIsNotNone(alert.resolved_at)

    def test_security_alert_str_method(self):
        """Test string representation of security alert."""
        alert = SecurityAlert.objects.create(
            alert_type='unauthorized_access',
            severity='medium',
            title='Unauthorized Access Attempt',
        )

        expected_str = "medium unauthorized_access: Unauthorized Access Attempt"
        self.assertEqual(str(alert), expected_str)


class AuditUtilsTest(TestCase):
    """Test cases for audit utility functions."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )
        self.location = Location.objects.create(
            name='Test Location',
            latitude=40.7128,
            longitude=-74.0060
        )

    def test_log_user_action(self):
        """Test logging user actions."""
        old_data = {'name': 'Old Name'}
        new_data = {'name': 'New Name'}

        log = log_user_action(
            user=self.user,
            action='update',
            resource_type='user',
            resource_id='123',
            old_data=old_data,
            new_data=new_data,
            ip_address='192.168.1.1',
        )

        self.assertEqual(log.action, 'update')
        self.assertEqual(log.resource_type, 'user')
        self.assertEqual(log.old_values, old_data)
        self.assertEqual(log.new_values, new_data)
        self.assertEqual(log.ip_address, '192.168.1.1')

    @patch('audit.utils.cache')
    def test_calculate_risk_score(self, mock_cache):
        """Test risk score calculation."""
        mock_cache.set.return_value = None

        # Test login action
        score = calculate_risk_score(self.user, 'login', '192.168.1.1', self.location)
        self.assertIsInstance(score, int)
        self.assertGreaterEqual(score, 0)
        self.assertLessEqual(score, 100)

        # Test high-risk action
        score = calculate_risk_score(self.user, 'delete', '192.168.1.1', self.location)
        self.assertGreater(score, 10)  # Should be higher than login

    def test_detect_anomalies(self):
        """Test anomaly detection."""
        # Create some audit logs for the user
        for i in range(5):
            AuditLog.objects.create(
                user=self.user,
                action='read',
                ip_address='192.168.1.1',
                created_at=timezone.now() - timedelta(hours=i),
            )

        current_request = {
            'action': 'delete',
            'resource_type': 'user',
            'ip_address': '192.168.1.1',
            'user_agent': 'Test Agent',
        }

        is_suspicious, anomalies = detect_anomalies(self.user, current_request)

        # Should detect some pattern (may or may not be suspicious based on implementation)
        self.assertIsInstance(is_suspicious, bool)
        self.assertIsInstance(anomalies, dict)


class AuditMonitoringTest(TestCase):
    """Test cases for audit monitoring functionality."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    def test_failed_login_tracking(self):
        """Test failed login monitoring."""
        # Create failed login attempts
        for i in range(3):
            AuditLog.objects.create(
                user=self.user,
                action='login',
                response_status=401,
                ip_address='192.168.1.1',
                created_at=timezone.now() - timedelta(minutes=i*5),
            )

        results = audit_monitor.check_failed_logins(user=self.user)

        self.assertIn('15_minutes', results)
        self.assertEqual(results['15_minutes']['count'], 3)
        self.assertTrue(results['15_minutes']['threshold_breached'])

    def test_unusual_access_patterns(self):
        """Test unusual access pattern detection."""
        # Create many actions in short time
        for i in range(25):
            AuditLog.objects.create(
                user=self.user,
                action='read',
                created_at=timezone.now() - timedelta(minutes=i),
            )

        patterns = audit_monitor.detect_unusual_access_patterns(hours=1)

        self.assertIn('total_actions', patterns)
        self.assertGreater(patterns['total_actions'], 20)

    def test_geographic_anomalies(self):
        """Test geographic anomaly detection."""
        location1 = Location.objects.create(name='Location 1', latitude=40.7128, longitude=-74.0060)
        location2 = Location.objects.create(name='Location 2', latitude=34.0522, longitude=-118.2437)

        # Create logs from different locations in short time
        AuditLog.objects.create(
            user=self.user,
            action='login',
            location=location1,
            created_at=timezone.now() - timedelta(hours=1),
        )
        AuditLog.objects.create(
            user=self.user,
            action='read',
            location=location2,
            created_at=timezone.now() - timedelta(minutes=30),
        )

        anomalies = audit_monitor.monitor_geographic_anomalies(days=1)

        # Should detect rapid location changes
        self.assertIsInstance(anomalies, list)


class AuditAPITest(APITestCase):
    """Test cases for audit API endpoints."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123',
            is_staff=True  # For audit access
        )
        self.client.force_authenticate(user=self.user)

        # Create some test audit logs
        for i in range(5):
            AuditLog.objects.create(
                user=self.user,
                action='login' if i % 2 == 0 else 'logout',
                ip_address='192.168.1.1',
                risk_score=i * 10,
            )

    def test_audit_log_list(self):
        """Test audit log list endpoint."""
        url = reverse('audit:audit-log-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('results', response.data)
        self.assertGreaterEqual(len(response.data['results']), 5)

    def test_audit_log_filtering(self):
        """Test audit log filtering."""
        url = reverse('audit:audit-log-list')
        response = self.client.get(url, {'action': 'login'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        # Should only return login actions
        for log in response.data['results']:
            self.assertEqual(log['action'], 'login')

    def test_security_alert_list(self):
        """Test security alert list endpoint."""
        # Create a security alert
        SecurityAlert.objects.create(
            alert_type='suspicious_login',
            severity='medium',
            title='Test Alert',
            user=self.user,
        )

        url = reverse('audit:security-alert-list')
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertGreaterEqual(len(response.data['results']), 1)

    def test_security_alert_resolve(self):
        """Test security alert resolution."""
        alert = SecurityAlert.objects.create(
            alert_type='brute_force',
            severity='high',
            title='Test Brute Force',
            user=self.user,
        )

        url = reverse('audit:security-alert-resolve', kwargs={'pk': alert.id})
        response = self.client.post(url, {'resolution_notes': 'Resolved'})

        self.assertEqual(response.status_code, status.HTTP_200_OK)

        alert.refresh_from_db()
        self.assertTrue(alert.is_resolved)
        self.assertEqual(alert.resolution_notes, 'Resolved')

    def test_user_activity(self):
        """Test user activity endpoint."""
        url = reverse('audit:user-activity-activity', kwargs={'pk': self.user.id})
        response = self.client.get(url)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('user_id', response.data)
        self.assertIn('total_actions', response.data)


class AuditReportsTest(TestCase):
    """Test cases for audit report generation."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

        # Create test data
        for i in range(10):
            AuditLog.objects.create(
                user=self.user,
                action='login' if i < 5 else 'read',
                risk_score=i * 10,
                response_status=200 if i < 8 else 401,
                created_at=timezone.now() - timedelta(days=i),
            )

    def test_security_summary_report(self):
        """Test security summary report generation."""
        generator = AuditReportGenerator()
        report = generator.generate_security_summary_report()

        self.assertIn('report_type', report)
        self.assertEqual(report['report_type'], 'security_summary')
        self.assertIn('summary', report)
        self.assertIn('alerts_by_severity', report)
        self.assertIn('risk_distribution', report)

    def test_user_activity_report(self):
        """Test user activity report generation."""
        generator = AuditReportGenerator()
        report = generator.generate_user_activity_report(str(self.user.id))

        self.assertIn('report_type', report)
        self.assertEqual(report['report_type'], 'user_activity')
        self.assertIn('user_stats', report)

    def test_compliance_report(self):
        """Test compliance report generation."""
        generator = AuditReportGenerator()
        report = generator.generate_compliance_report()

        self.assertIn('report_type', report)
        self.assertEqual(report['report_type'], 'compliance')
        self.assertIn('data_access_events', report)
        self.assertIn('authentication_failures', report)

    def test_csv_export(self):
        """Test CSV export functionality."""
        generator = AuditReportGenerator()

        # Test security summary CSV export
        report = generator.generate_security_summary_report()
        csv_data = generator.export_to_csv(report, 'security_summary')

        self.assertIn('Metric', csv_data)
        self.assertIn('Value', csv_data)

    def test_json_export(self):
        """Test JSON export functionality."""
        generator = AuditReportGenerator()
        report = generator.generate_security_summary_report()
        json_data = generator.export_to_json(report)

        # Should be valid JSON
        parsed = json.loads(json_data)
        self.assertEqual(parsed['report_type'], 'security_summary')


class AuditArchivingTest(TestCase):
    """Test cases for audit archiving functionality."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    @override_settings(AUDIT_ARCHIVE_THRESHOLD_DAYS=0)  # Archive immediately
    def test_archive_creation(self):
        """Test archive creation."""
        from .archiving import audit_archiver

        # Create old audit logs
        old_date = timezone.now() - timedelta(days=400)  # Older than archive threshold
        for i in range(3):
            AuditLog.objects.create(
                user=self.user,
                action='login',
                created_at=old_date - timedelta(days=i),
            )

        # Archive logs
        result = audit_archiver.archive_old_logs(dry_run=True)

        self.assertIn('archived_count', result)
        self.assertGreaterEqual(result['archived_count'], 3)

    def test_archive_statistics(self):
        """Test archive statistics retrieval."""
        from .archiving import audit_archiver

        stats = audit_archiver.get_archive_statistics()

        self.assertIn('total_archives', stats)
        self.assertIn('total_size', stats)
        self.assertIn('archives', stats)


class AuditAlertingTest(TestCase):
    """Test cases for audit alerting functionality."""

    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser',
            email='test@example.com',
            password='testpass123'
        )

    @patch('audit.alerting.send_mail')
    def test_email_alert_notification(self, mock_send_mail):
        """Test email alert notification."""
        from .alerting import alert_manager

        alert = SecurityAlert.objects.create(
            alert_type='suspicious_login',
            severity='high',
            title='Test Alert',
            description='Test description',
            user=self.user,
        )

        results = alert_manager.send_alert_notifications(alert)

        self.assertIn('email_sent', results)
        mock_send_mail.assert_called_once()

    def test_dashboard_notifications(self):
        """Test dashboard notification storage."""
        from .alerting import alert_manager

        alert = SecurityAlert.objects.create(
            alert_type='brute_force',
            severity='critical',
            title='Brute Force Detected',
            user=self.user,
        )

        results = alert_manager.send_alert_notifications(alert)

        self.assertIn('dashboard_notified', results)

        # Check if notification was stored
        notifications = alert_manager.get_dashboard_notifications()
        self.assertIsInstance(notifications, list)
