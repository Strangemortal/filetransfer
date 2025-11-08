from django.core.management.base import BaseCommand
from django.utils import timezone
from datetime import timedelta
from transfer.models import FileTransfer
import os


class Command(BaseCommand):
    help = 'Delete files that have been opened and exceeded the 10-minute auto-delete timer'

    def handle(self, *args, **kwargs):
        # Find files that should be auto-deleted
        cutoff_time = timezone.now() - timedelta(minutes=10)
        expired_files = FileTransfer.objects.filter(
            auto_delete=True,
            opened_at__isnull=False,
            opened_at__lte=cutoff_time
        )

        deleted_count = 0
        for file_transfer in expired_files:
            try:
                # Delete physical file
                if file_transfer.file and os.path.isfile(file_transfer.file.path):
                    os.remove(file_transfer.file.path)
                # Delete database record
                file_transfer.delete()
                deleted_count += 1
                self.stdout.write(f"Deleted: {file_transfer}")
            except Exception as e:
                self.stderr.write(f"Error deleting {file_transfer}: {str(e)}")

        self.stdout.write(
            self.style.SUCCESS(f'Successfully deleted {deleted_count} expired file(s)')
        )
