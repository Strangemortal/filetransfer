from django import forms
from .models import FileTransfer
from django.contrib.auth import get_user_model

User = get_user_model()

class FileTransferForm(forms.ModelForm):
    receiver_username = forms.CharField(
        max_length=150,
        help_text='Enter the username of the receiver'
    )
    auto_delete = forms.BooleanField(
        required=False,
        initial=False,
        help_text='Automatically delete file 10 minutes after recipient opens it'
    )

    class Meta:
        model = FileTransfer
        fields = ['file', 'description', 'receiver_username', 'auto_delete']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }

    def clean_receiver_username(self):
        username = self.cleaned_data.get('receiver_username')
        try:
            receiver = User.objects.get(username=username)
        except User.DoesNotExist:
            raise forms.ValidationError('User does not exist')
        return username