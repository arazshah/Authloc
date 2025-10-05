"""
Management commands for audit data retention and cleanup.
"""

from datetime import timedelta
from typing import Dict, List

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction
from django.utils import timezone

from audit.models import AuditLog, SecurityAlert


class Command(BaseCommand):
    help = 'Clean up old audit data based on retention policies'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting',
        )
        parser.add_argument(
            '--audit-logs-days',
            type=int,
            default=365,
            help='Retain audit logs for this many days (default: 365)',
        )
        parser.add_argument(
            '--security-alerts-days',
            type=int,
            default=730,
            help='Retain security alerts for this many days (default: 730)',
        )
        parser.add_argument(
            '--force',
            action='store_true',
            help='Force deletion without confirmation',
        )

    def handle(self, *args, **options):
        dry_run = options['dry_run']
        audit_logs_days = options['audit_logs_days']
        security_alerts_days = options['security_alerts_days']
        force = options['force']

        self.stdout.write(
            self.style.WARNING(
                f"Starting audit data cleanup (dry_run: {dry_run})"
            )
        )

        # Calculate cutoff dates
        now = timezone.now()
        audit_cutoff = now - timedelta(days=audit_logs_days)
        alert_cutoff = now - timedelta(days=security_alerts_days)

        self.stdout.write(f"Audit logs older than: {audit_cutoff}")
        self.stdout.write(f"Security alerts older than: {alert_cutoff}")

        # Get counts of data to be deleted
        audit_logs_to_delete = AuditLog.objects.filter(created_at__lt=audit_cutoff)
        security_alerts_to_delete = SecurityAlert.objects.filter(created_at__lt=alert_cutoff)

        audit_count = audit_logs_to_delete.count()
        alert_count = security_alerts_to_delete.count()

        self.stdout.write(
            self.style.SUCCESS(
                f"Found {audit_count} audit logs and {alert_count} security alerts to delete"
            )
        )

        if audit_count == 0 and alert_count == 0:
            self.stdout.write("No data to clean up.")
            return

        # Show summary
        if dry_run:
            self.stdout.write(
                self.style.WARNING("DRY RUN - No data will be deleted")
            )
        else:
            if not force:
                # Ask for confirmation
                self.stdout.write(
                    self.style.WARNING(
                        f"This will permanently delete {audit_count} audit logs "
                        f"and {alert_count} security alerts."
                    )
                )
                confirm = input("Are you sure you want to continue? (yes/no): ")
                if confirm.lower() != 'yes':
                    self.stdout.write("Operation cancelled.")
                    return

        # Perform cleanup
        try:
            with transaction.atomic():
                if not dry_run:
                    deleted_audits = audit_logs_to_delete.delete()
                    deleted_alerts = security_alerts_to_delete.delete()

                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Successfully deleted {deleted_audits[0]} audit logs "
                            f"and {deleted_alerts[0]} security alerts"
                        )
                    )
                else:
                    self.stdout.write(
                        self.style.SUCCESS(
                            f"Would delete {audit_count} audit logs "
                            f"and {alert_count} security alerts"
                        )
                    )

        except Exception as e:
            raise CommandError(f"Error during cleanup: {e}")

        # Show retention summary
        self.show_retention_summary()

    def show_retention_summary(self):
        """Show current data retention summary."""
        now = timezone.now()

        # Audit logs by age
        age_ranges = [
            (7, "Last 7 days"),
            (30, "Last 30 days"),
            (90, "Last 90 days"),
            (365, "Last year"),
            (9999, "Older than 1 year"),
        ]

        self.stdout.write("\nAudit Log Retention Summary:")
        for days, label in age_ranges:
            if days == 9999:
                count = AuditLog.objects.filter(created_at__lt=now - timedelta(days=365)).count()
            else:
                count = AuditLog.objects.filter(
                    created_at__gte=now - timedelta(days=days),
                    created_at__lt=now - timedelta(days=days-7) if days > 7 else now
                ).count()
            self.stdout.write(f"  {label}: {count} logs")

        # Security alerts by age
        self.stdout.write("\nSecurity Alert Retention Summary:")
        for days, label in age_ranges:
            if days == 9999:
                count = SecurityAlert.objects.filter(created_at__lt=now - timedelta(days=365)).count()
            else:
                count = SecurityAlert.objects.filter(
                    created_at__gte=now - timedelta(days=days),
                    created_at__lt=now - timedelta(days=days-7) if days > 7 else now
                ).count()
            self.stdout.write(f"  {label}: {count} alerts")
