# transfer/management/commands/cleanup_old_files.py

import os
from django.core.management.base import BaseCommand
from django.utils import timezone
from transfer.models import FileTransfer

class Command(BaseCommand):
    help = 'Deletes FileTransfer records and actual files older than X days'

    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=7,  # change default if desired
            help='Delete files older than this number of days'
        )

    def handle(self, *args, **options):
        days = options['days']
        cutoff = timezone.now() - timezone.timedelta(days=days)
        old_files = FileTransfer.objects.filter(uploaded_at__lt=cutoff)

        count = 0
        for obj in old_files:
            file_path = obj.file.path
            if os.path.isfile(file_path):
                os.remove(file_path)
            obj.delete()
            count += 1
        self.stdout.write(f"Deleted {count} file(s) older than {days} days.")
