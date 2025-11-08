from django.contrib import admin
from .models import FileTransfer
@admin.register(FileTransfer)
class FileTransferAdmin(admin.ModelAdmin):
    list_display = ['sender', 'receiver', 'file', 'uploaded_at', 'is_read']
    list_filter = ['uploaded_at', 'is_read']
    search_fields = ['sender__username', 'receiver__username', 'description']
    readonly_fields = ['uploaded_at']