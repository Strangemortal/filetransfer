from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, authenticate, logout
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib import messages
from django.contrib.auth import get_user_model
from .models import FileTransfer
from .forms import FileTransferForm
from django.http import HttpResponseRedirect, JsonResponse
from django.urls import reverse
from django.utils import timezone
import os

User = get_user_model()

def register(request):
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        if form.is_valid():
            user = form.save()
            username = form.cleaned_data.get('username')
            messages.success(request, f'Account created for {username}!')
            login(request, user)
            return redirect('home')
    else:
        form = UserCreationForm()
    return render(request, 'transfer/register.html', {'form': form})

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                return redirect('home')
            else:
                messages.error(request, 'Invalid username or password')
        else:
            messages.error(request, 'Invalid username or password')
    else:
        form = AuthenticationForm()
    return render(request, 'transfer/login.html', {'form': form})

@login_required
def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out')
    return redirect('login')

@login_required
def home(request):
    sent_files = FileTransfer.objects.filter(sender=request.user)
    received_files = FileTransfer.objects.filter(receiver=request.user)
    return render(request, 'transfer/home.html', {
        'sent_files': sent_files,
        'received_files': received_files
    })

@login_required
def upload_file(request):
    if request.method == 'POST':
        form = FileTransferForm(request.POST, request.FILES)
        if form.is_valid():
            file_transfer = form.save(commit=False)
            file_transfer.sender = request.user
            receiver_username = form.cleaned_data['receiver_username']
            file_transfer.receiver = User.objects.get(username=receiver_username)
            file_transfer.save()
            messages.success(request, 'File uploaded and sent successfully!')
            return redirect('home')
    else:
        form = FileTransferForm()
    return render(request, 'transfer/upload.html', {'form': form})

@login_required


def delete_file(request, pk):
    file_transfer = get_object_or_404(FileTransfer, pk=pk)
    # Only sender or receiver can delete
    if request.user in [file_transfer.sender, file_transfer.receiver]:
        # Delete file from storage
        file_path = file_transfer.file.path
        file_transfer.delete()
        if os.path.isfile(file_path):
            os.remove(file_path)
        messages.success(request, "File deleted successfully!")
    else:
        messages.error(request, "You don't have permission to delete this file.")
    return HttpResponseRedirect(reverse('home'))
def file_detail(request, pk):
    file_transfer = get_object_or_404(FileTransfer, pk=pk)
    if request.user not in [file_transfer.sender, file_transfer.receiver]:
        messages.error(request, 'You do not have permission to view this file')
        return redirect('home')

    if request.user == file_transfer.receiver:
        if not file_transfer.is_read:
            file_transfer.is_read = True
            # Track when file was opened for auto-delete
            if file_transfer.auto_delete and not file_transfer.opened_at:
                file_transfer.opened_at = timezone.now()
            file_transfer.save()

    return render(request, 'transfer/file_detail.html', {'file_transfer': file_transfer})


@login_required
def get_file_updates(request):
    """API endpoint for polling file list updates"""
    sent_files = FileTransfer.objects.filter(sender=request.user)
    received_files = FileTransfer.objects.filter(receiver=request.user)

    def serialize_file(file_obj):
        return {
            'id': file_obj.pk,
            'is_read': file_obj.is_read,
            'auto_delete': file_obj.auto_delete,
            'opened_at': file_obj.opened_at.isoformat() if file_obj.opened_at else None,
        }

    return JsonResponse({
        'sent_files': [serialize_file(f) for f in sent_files],
        'received_files': [serialize_file(f) for f in received_files],
        'sent_count': sent_files.count(),
        'received_count': received_files.count(),
    })