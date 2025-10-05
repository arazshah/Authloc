"""
Real-time alerting system for security events.

Provides email, SMS, and dashboard notifications for security alerts.
"""

import logging
from typing import Dict, List, Optional

from django.conf import settings
from django.core.mail import send_mail
from django.template.loader import render_to_string
from django.utils import timezone

from .models import SecurityAlert

logger = logging.getLogger(__name__)


class AlertNotificationManager:
    """
    Manager for sending security alert notifications.

    Supports multiple notification channels: email, SMS, and dashboard notifications.
    """

    def __init__(self):
        self.email_enabled = getattr(settings, 'AUDIT_EMAIL_ALERTS_ENABLED', True)
        self.sms_enabled = getattr(settings, 'AUDIT_SMS_ALERTS_ENABLED', False)
        self.dashboard_enabled = getattr(settings, 'AUDIT_DASHBOARD_ALERTS_ENABLED', True)

        # Email settings
        self.alert_email_recipients = getattr(settings, 'AUDIT_ALERT_EMAIL_RECIPIENTS', [])
        self.from_email = getattr(settings, 'AUDIT_FROM_EMAIL', settings.DEFAULT_FROM_EMAIL)

        # SMS settings (would integrate with SMS service like Twilio)
        self.sms_service_enabled = getattr(settings, 'AUDIT_SMS_SERVICE_ENABLED', False)

    def send_alert_notifications(self, alert: SecurityAlert) -> Dict[str, bool]:
        """
        Send notifications for a security alert based on its severity.

        Args:
            alert: The security alert to notify about

        Returns:
            Dict with notification results
        """
        results = {
            'email_sent': False,
            'sms_sent': False,
            'dashboard_notified': False,
        }

        # Determine notification channels based on severity
        channels = self._get_notification_channels(alert.severity)

        # Send email notification
        if 'email' in channels and self.email_enabled:
            try:
                self._send_email_alert(alert)
                results['email_sent'] = True
            except Exception as e:
                logger.error(f"Failed to send email alert for {alert.id}: {e}")

        # Send SMS notification
        if 'sms' in channels and self.sms_enabled and self.sms_service_enabled:
            try:
                self._send_sms_alert(alert)
                results['sms_sent'] = True
            except Exception as e:
                logger.error(f"Failed to send SMS alert for {alert.id}: {e}")

        # Send dashboard notification
        if 'dashboard' in channels and self.dashboard_enabled:
            try:
                self._send_dashboard_notification(alert)
                results['dashboard_notified'] = True
            except Exception as e:
                logger.error(f"Failed to send dashboard notification for {alert.id}: {e}")

        return results

    def _get_notification_channels(self, severity: str) -> List[str]:
        """
        Determine which notification channels to use based on alert severity.

        Args:
            severity: Alert severity (low, medium, high, critical)

        Returns:
            List of notification channels
        """
        channels = []

        if severity in ['high', 'critical']:
            channels.extend(['email', 'dashboard'])
            if severity == 'critical':
                channels.append('sms')
        elif severity == 'medium':
            channels.extend(['email', 'dashboard'])
        elif severity == 'low':
            channels.append('dashboard')

        return channels

    def _send_email_alert(self, alert: SecurityAlert):
        """Send email notification for security alert."""
        subject = f"Security Alert: {alert.severity.upper()} - {alert.title}"

        context = {
            'alert': alert,
            'alert_type_display': alert.get_alert_type_display(),
            'severity_display': alert.get_severity_display(),
            'timestamp': timezone.now(),
        }

        # Render HTML email template
        html_message = render_to_string('audit/email/security_alert.html', context)

        # Plain text fallback
        text_message = render_to_string('audit/email/security_alert.txt', context)

        send_mail(
            subject=subject,
            message=text_message,
            from_email=self.from_email,
            recipient_list=self.alert_email_recipients,
            html_message=html_message,
            fail_silently=False,
        )

        logger.info(f"Sent email alert for security alert {alert.id}")

    def _send_sms_alert(self, alert: SecurityAlert):
        """Send SMS notification for critical security alerts."""
        # This would integrate with SMS service like Twilio, AWS SNS, etc.
        # For now, just log the SMS that would be sent

        sms_message = f"CRITICAL SECURITY ALERT: {alert.title} - Severity: {alert.severity.upper()}"

        # Example integration with Twilio (commented out):
        # from twilio.rest import Client
        # client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        # for phone_number in self.sms_recipients:
        #     client.messages.create(
        #         body=sms_message,
        #         from_=settings.TWILIO_PHONE_NUMBER,
        #         to=phone_number
        #     )

        logger.warning(f"SMS ALERT (not implemented): {sms_message}")
        logger.info(f"Would send SMS alert for critical security alert {alert.id}")

    def _send_dashboard_notification(self, alert: SecurityAlert):
        """Send dashboard notification for security alert."""
        # This would integrate with WebSocket channels or similar real-time system
        # For now, create a dashboard notification record or use Django channels

        from django.core.cache import cache

        # Store notification in cache for dashboard to pick up
        notification_key = f"dashboard_alert_{alert.id}"
        notification_data = {
            'id': str(alert.id),
            'type': 'security_alert',
            'severity': alert.severity,
            'title': alert.title,
            'description': alert.description,
            'timestamp': alert.created_at.isoformat(),
            'user': alert.user.get_username() if alert.user else None,
        }

        # Store for 24 hours
        cache.set(notification_key, notification_data, 86400)

        # Also add to a global list of active notifications
        active_notifications = cache.get('active_dashboard_notifications', [])
        active_notifications.append(notification_data)

        # Keep only last 50 notifications
        active_notifications = active_notifications[-50:]
        cache.set('active_dashboard_notifications', active_notifications, 86400)

        logger.info(f"Created dashboard notification for security alert {alert.id}")

    def send_batch_notifications(self, alerts: List[SecurityAlert]) -> Dict[str, int]:
        """
        Send notifications for multiple alerts efficiently.

        Args:
            alerts: List of security alerts

        Returns:
            Dict with counts of successful notifications by channel
        """
        results = {
            'email_sent': 0,
            'sms_sent': 0,
            'dashboard_notified': 0,
        }

        for alert in alerts:
            alert_results = self.send_alert_notifications(alert)
            for channel, success in alert_results.items():
                if success:
                    results[channel] += 1

        return results

    def get_dashboard_notifications(self, user=None) -> List[Dict]:
        """
        Get active dashboard notifications for a user.

        Args:
            user: User to get notifications for (optional)

        Returns:
            List of dashboard notifications
        """
        from django.core.cache import cache

        notifications = cache.get('active_dashboard_notifications', [])

        # Filter by user if specified
        if user:
            notifications = [
                n for n in notifications
                if n.get('user') == user.get_username()
            ]

        return notifications

    def clear_dashboard_notification(self, alert_id: str):
        """
        Clear a specific dashboard notification.

        Args:
            alert_id: ID of the alert notification to clear
        """
        from django.core.cache import cache

        # Remove from active notifications
        active_notifications = cache.get('active_dashboard_notifications', [])
        active_notifications = [
            n for n in active_notifications
            if n.get('id') != alert_id
        ]
        cache.set('active_dashboard_notifications', active_notifications, 86400)

        # Remove individual notification
        notification_key = f"dashboard_alert_{alert_id}"
        cache.delete(notification_key)


# Global alert notification manager instance
alert_manager = AlertNotificationManager()


def send_security_alert_notification(alert: SecurityAlert) -> Dict[str, bool]:
    """
    Convenience function to send notifications for a security alert.

    Args:
        alert: Security alert to notify about

    Returns:
        Dict with notification results
    """
    return alert_manager.send_alert_notifications(alert)


def get_user_dashboard_notifications(user) -> List[Dict]:
    """
    Get dashboard notifications for a specific user.

    Args:
        user: User to get notifications for

    Returns:
        List of dashboard notifications
    """
    return alert_manager.get_dashboard_notifications(user)
