from django.shortcuts import render

# Create your views here.

# accounts/views.py

from django.shortcuts import render, redirect
from django.contrib.auth import login, authenticate
from django.contrib.auth.forms import AuthenticationForm, PasswordResetForm
from django.contrib.auth.views import PasswordChangeView, PasswordResetConfirmView
from django.contrib.auth.decorators import login_required
from django.urls import reverse_lazy
from django.contrib.auth.models import User
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from django.contrib.auth.tokens import default_token_generator
from django.core.mail import EmailMessage
from .forms import SignUpForm, CustomPasswordChangeForm

def login_view(request):
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(username=username, password=password)
            if user is not None:
                login(request, user)
                return redirect('dashboard')
    else:
        form = AuthenticationForm()
    return render(request, 'accounts/login.html', {'form': form})

from django.contrib import messages
from django.contrib.auth import login
from django.shortcuts import render, redirect
from .forms import SignUpForm

def signup_view(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            # Save the user data
            user = form.save()
            # Log the user in immediately after successful signup
            login(request, user)
            return redirect('dashboard')  # Redirect to dashboard after login
        else:
            # Print form errors to the console (useful for debugging)
            print(form.errors)  # Add this line to see form validation errors in your console
            messages.error(request, 'Error during signup. Please try again.')  # Show an error message if form is invalid
    else:
        form = SignUpForm()

    return render(request, 'accounts/signup.html', {'form': form})



def forgot_password_view(request):
    if request.method == 'POST':
        password_reset_form = PasswordResetForm(request.POST)
        if password_reset_form.is_valid():
            data = password_reset_form.cleaned_data['email']
            associated_users = User.objects.filter(email=data)
            if associated_users.exists():
                for user in associated_users:
                    subject = "Password Reset Requested"
                    email_template_name = "accounts/password_reset_email.txt"
                    c = {
                        "email": user.email,
                        'domain': 'example.com',
                        'site_name': 'Website',
                        "uid": urlsafe_base64_encode(force_bytes(user.pk)),
                        "user": user,
                        'token': default_token_generator.make_token(user),
                        'protocol': 'http',
                    }
                    email = render_to_string(email_template_name, c)
                    try:
                        send_email = EmailMessage(subject, email, to=[user.email])
                        send_email.send()
                    except:
                        return redirect("/password_reset/done/")
    password_reset_form = PasswordResetForm()
    return render(request, 'accounts/forgot_password.html', {'password_reset_form': password_reset_form})

class CustomPasswordChangeView(PasswordChangeView):
    form_class = CustomPasswordChangeForm
    success_url = reverse_lazy('dashboard')

@login_required
def dashboard_view(request):
    return render(request, 'accounts/dashboard.html')

@login_required
def profile_view(request):
    return render(request, 'accounts/profile.html')
