"""
Audit log compression and archiving system.

Provides mechanisms to compress, archive, and manage large volumes of audit data.
"""

import gzip
import json
import logging
import os
import shutil
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional

from django.conf import settings
from django.core.files.base import ContentFile
from django.core.files.storage import default_storage
from django.db import transaction
from django.utils import timezone

from .models import AuditLog

logger = logging.getLogger(__name__)


class AuditArchiver:
    """
    Handles compression and archiving of audit logs.

    Provides functionality to:
    - Compress old audit logs into archive files
    - Move archives to external storage
    - Retrieve archived data when needed
    - Manage archive retention policies
    """

    def __init__(self):
        self.archive_base_path = getattr(settings, 'AUDIT_ARCHIVE_PATH', 'audit_archives')
        self.compression_level = getattr(settings, 'AUDIT_COMPRESSION_LEVEL', 9)
        self.archive_threshold_days = getattr(settings, 'AUDIT_ARCHIVE_THRESHOLD_DAYS', 1095)  # 3 years
        self.archive_retention_years = getattr(settings, 'AUDIT_ARCHIVE_RETENTION_YEARS', 7)

        # Ensure archive directory exists
        Path(self.archive_base_path).mkdir(parents=True, exist_ok=True)

    def archive_old_logs(self, dry_run: bool = False) -> Dict[str, any]:
        """
        Archive audit logs older than the threshold.

        Args:
            dry_run: If True, only simulate the archiving process

        Returns:
            Dict with archiving results
        """
        cutoff_date = timezone.now() - timedelta(days=self.archive_threshold_days)

        # Get logs to archive
        logs_to_archive = AuditLog.objects.filter(
            created_at__lt=cutoff_date
        ).order_by('created_at')

        total_logs = logs_to_archive.count()

        if total_logs == 0:
            return {
                'archived_count': 0,
                'archives_created': 0,
                'message': 'No logs to archive'
            }

        logger.info(f"Starting archive of {total_logs} audit logs older than {cutoff_date}")

        # Group logs by month for archiving
        monthly_groups = {}
        for log in logs_to_archive.values():
            month_key = log['created_at'].strftime('%Y-%m')
            if month_key not in monthly_groups:
                monthly_groups[month_key] = []
            monthly_groups[month_key].append(log)

        archives_created = 0
        archived_count = 0

        for month_key, logs in monthly_groups.items():
            try:
                archive_path = self._create_monthly_archive(month_key, logs, dry_run)
                if archive_path:
                    archives_created += 1
                    archived_count += len(logs)

                    if not dry_run:
                        # Mark logs as archived in database
                        log_ids = [log['id'] for log in logs]
                        AuditLog.objects.filter(id__in=log_ids).update(
                            metadata={'archived': True, 'archive_path': archive_path}
                        )

            except Exception as e:
                logger.error(f"Failed to archive logs for {month_key}: {e}")

        if not dry_run and archived_count > 0:
            # Delete archived logs from database
            logs_to_archive.delete()

        return {
            'archived_count': archived_count,
            'archives_created': archives_created,
            'dry_run': dry_run,
            'message': f"Successfully archived {archived_count} logs into {archives_created} archives"
        }

    def cleanup_old_archives(self, dry_run: bool = False) -> Dict[str, any]:
        """
        Clean up archives older than retention period.

        Args:
            dry_run: If True, only simulate the cleanup

        Returns:
            Dict with cleanup results
        """
        retention_cutoff = timezone.now() - timedelta(days=self.archive_retention_years * 365)

        archives_cleaned = 0
        total_size_cleaned = 0

        # Get all archive files
        archive_dir = Path(self.archive_base_path)
        if not archive_dir.exists():
            return {'archives_cleaned': 0, 'message': 'No archive directory found'}

        for archive_file in archive_dir.glob('*.json.gz'):
            try:
                # Extract date from filename (format: audit_logs_YYYY-MM.json.gz)
                filename = archive_file.name
                if '_20' in filename:  # Look for year pattern
                    date_str = filename.split('_')[2].split('.')[0]  # Extract YYYY-MM
                    archive_date = datetime.strptime(date_str, '%Y-%m')

                    if archive_date < retention_cutoff:
                        file_size = archive_file.stat().st_size
                        total_size_cleaned += file_size

                        if not dry_run:
                            archive_file.unlink()
                            logger.info(f"Deleted old archive: {filename} ({file_size} bytes)")
                        else:
                            logger.info(f"Would delete old archive: {filename} ({file_size} bytes)")

                        archives_cleaned += 1

            except (ValueError, IndexError) as e:
                logger.warning(f"Could not parse archive filename {filename}: {e}")

        return {
            'archives_cleaned': archives_cleaned,
            'total_size_cleaned': total_size_cleaned,
            'dry_run': dry_run,
            'message': f"Cleaned up {archives_cleaned} old archives ({total_size_cleaned} bytes)"
        }

    def retrieve_archived_logs(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """
        Retrieve archived logs for a date range.

        Args:
            start_date: Start of date range
            end_date: End of date range

        Returns:
            List of archived log entries
        """
        archived_logs = []

        # Find relevant archive files
        start_month = start_date.strftime('%Y-%m')
        end_month = end_date.strftime('%Y-%m')

        archive_dir = Path(self.archive_base_path)

        for archive_file in archive_dir.glob('*.json.gz'):
            try:
                filename = archive_file.name
                if '_20' in filename:
                    file_month = filename.split('_')[2].split('.')[0]

                    # Check if this archive file covers our date range
                    if start_month <= file_month <= end_month:
                        logs = self._read_archive_file(str(archive_file))
                        # Filter logs within our date range
                        for log in logs:
                            log_date = datetime.fromisoformat(log['created_at'].replace('Z', '+00:00'))
                            if start_date <= log_date <= end_date:
                                archived_logs.append(log)

            except Exception as e:
                logger.error(f"Error reading archive file {archive_file}: {e}")

        return archived_logs

    def get_archive_statistics(self) -> Dict[str, any]:
        """
        Get statistics about archived data.

        Returns:
            Dict with archive statistics
        """
        archive_dir = Path(self.archive_base_path)
        if not archive_dir.exists():
            return {'total_archives': 0, 'total_size': 0, 'archives': []}

        archives = []
        total_size = 0

        for archive_file in archive_dir.glob('*.json.gz'):
            try:
                stat = archive_file.stat()
                file_size = stat.st_size
                total_size += file_size

                # Extract metadata from filename
                filename = archive_file.name
                parts = filename.split('_')
                if len(parts) >= 3:
                    date_str = parts[2].split('.')[0]
                    try:
                        archive_date = datetime.strptime(date_str, '%Y-%m')
                        archives.append({
                            'filename': filename,
                            'date': archive_date.isoformat(),
                            'size': file_size,
                            'size_mb': round(file_size / (1024 * 1024), 2),
                        })
                    except ValueError:
                        pass

            except Exception as e:
                logger.error(f"Error reading archive file {archive_file}: {e}")

        return {
            'total_archives': len(archives),
            'total_size': total_size,
            'total_size_mb': round(total_size / (1024 * 1024), 2),
            'archives': sorted(archives, key=lambda x: x['date'], reverse=True),
        }

    def _create_monthly_archive(self, month_key: str, logs: List[Dict], dry_run: bool = False) -> Optional[str]:
        """
        Create a compressed archive for a month's worth of logs.

        Args:
            month_key: Month key in YYYY-MM format
            logs: List of log data
            dry_run: If True, don't actually create the archive

        Returns:
            Path to created archive file, or None if failed
        """
        archive_filename = f"audit_logs_{month_key}.json.gz"
        archive_path = os.path.join(self.archive_base_path, archive_filename)

        if dry_run:
            logger.info(f"DRY RUN: Would create archive {archive_path} with {len(logs)} logs")
            return archive_path

        try:
            # Convert logs to JSON
            json_data = json.dumps(logs, default=str, indent=None)

            # Compress and write to file
            with gzip.open(archive_path, 'wt', compresslevel=self.compression_level, encoding='utf-8') as f:
                f.write(json_data)

            # Get file size for logging
            file_size = os.path.getsize(archive_path)
            compression_ratio = len(json_data.encode('utf-8')) / file_size

            logger.info(
                f"Created archive {archive_filename}: "
                f"{len(logs)} logs, {file_size} bytes, "
                f"compression ratio: {compression_ratio:.2f}"
            )

            return archive_path

        except Exception as e:
            logger.error(f"Failed to create archive {archive_filename}: {e}")
            # Clean up partial file if it exists
            if os.path.exists(archive_path):
                os.remove(archive_path)
            return None

    def _read_archive_file(self, archive_path: str) -> List[Dict]:
        """
        Read logs from an archive file.

        Args:
            archive_path: Path to the archive file

        Returns:
            List of log entries
        """
        try:
            with gzip.open(archive_path, 'rt', encoding='utf-8') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except Exception as e:
            logger.error(f"Failed to read archive file {archive_path}: {e}")
            return []

    def move_archives_to_storage(self, storage_path: str = None) -> Dict[str, any]:
        """
        Move archive files to external storage (e.g., cloud storage).

        Args:
            storage_path: Optional custom storage path

        Returns:
            Dict with results of the move operation
        """
        if not storage_path:
            storage_path = getattr(settings, 'AUDIT_ARCHIVE_STORAGE_PATH', 'archives/audit/')

        archive_dir = Path(self.archive_base_path)
        if not archive_dir.exists():
            return {'moved': 0, 'message': 'No archive directory found'}

        moved_count = 0
        total_size = 0

        for archive_file in archive_dir.glob('*.json.gz'):
            try:
                # Read file content
                with open(archive_file, 'rb') as f:
                    file_content = f.read()

                # Upload to storage
                storage_file_path = f"{storage_path}{archive_file.name}"
                file_obj = ContentFile(file_content)
                default_storage.save(storage_file_path, file_obj)

                # Verify upload and delete local file
                if default_storage.exists(storage_file_path):
                    file_size = archive_file.stat().st_size
                    total_size += file_size
                    archive_file.unlink()
                    moved_count += 1
                    logger.info(f"Moved archive to storage: {archive_file.name}")

            except Exception as e:
                logger.error(f"Failed to move archive {archive_file.name}: {e}")

        return {
            'moved': moved_count,
            'total_size': total_size,
            'message': f"Successfully moved {moved_count} archives to storage"
        }


# Global archiver instance
audit_archiver = AuditArchiver()


def archive_audit_logs(dry_run: bool = False) -> Dict[str, any]:
    """
    Convenience function to archive old audit logs.

    Args:
        dry_run: If True, simulate archiving

    Returns:
        Dict with archiving results
    """
    return audit_archiver.archive_old_logs(dry_run=dry_run)


def cleanup_audit_archives(dry_run: bool = False) -> Dict[str, any]:
    """
    Convenience function to clean up old audit archives.

    Args:
        dry_run: If True, simulate cleanup

    Returns:
        Dict with cleanup results
    """
    return audit_archiver.cleanup_old_archives(dry_run=dry_run)
