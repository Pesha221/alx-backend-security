# ip_tracking/views.py
from django.shortcuts import render
from django.http import JsonResponse
from django.utils import timezone
from datetime import timedelta
from .models import RequestLog

def test_logging_view(request):
    """
    Test view to verify IP logging is working.
    """
    # This view will be logged by the middleware
    return JsonResponse({
        'message': 'IP logging test successful',
        'your_ip': request.META.get('REMOTE_ADDR'),
        'timestamp': timezone.now().isoformat(),
        'path': request.path,
    })

def view_logs(request):
    """
    View to see recent logs (for testing purposes).
    """
    # Get recent logs (last 100)
    recent_logs = RequestLog.objects.all().order_by('-timestamp')[:100]
    
    # Get statistics
    total_logs = RequestLog.objects.count()
    today_logs = RequestLog.objects.filter(
        timestamp__gte=timezone.now() - timedelta(hours=24)
    ).count()
    
    unique_ips = RequestLog.objects.values('ip_address').distinct().count()
    
    context = {
        'recent_logs': recent_logs,
        'total_logs': total_logs,
        'today_logs': today_logs,
        'unique_ips': unique_ips,
        'page_title': 'IP Logging Dashboard',
    }
    
    return render(request, 'ip_tracking/logs.html', context)

def api_logs(request):
    """
    API endpoint to get logs in JSON format.
    """
    # Optional: Add authentication/authorization here
    logs = RequestLog.objects.all().order_by('-timestamp')[:50]
    
    data = {
        'logs': [
            {
                'ip_address': log.ip_address,
                'path': log.path,
                'method': log.method,
                'timestamp': log.timestamp.isoformat(),
                'user': log.user.username if log.user else None,
                'status_code': log.status_code,
                'response_time': log.response_time,
                'user_agent': log.user_agent[:100] if log.user_agent else None,
            }
            for log in logs
        ],
        'count': logs.count(),
        'timestamp': timezone.now().isoformat(),
    }
    
    return JsonResponse(data)

# ip_tracking/views.py
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.forms import AuthenticationForm, UserCreationForm, PasswordResetForm
from django.contrib import messages
from django.http import JsonResponse, HttpResponseForbidden
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.views.generic import View, TemplateView
from django.contrib.auth.decorators import login_required
from django.views.decorators.csrf import csrf_protect
import logging

# Import rate limit utilities
from .ratelimit_utils import (
    rate_limit_decorator, 
    get_client_ip,
    RateLimitManager
)
from django_ratelimit.decorators import ratelimit
from django_ratelimit.core import is_ratelimited

logger = logging.getLogger(__name__)

# Custom login view with rate limiting
@csrf_protect
@require_http_methods(["GET", "POST"])
@rate_limit_decorator(limit='3/minute', key='login', method='POST')
def custom_login_view(request):
    """
    Custom login view with rate limiting.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = AuthenticationForm(request, data=request.POST)
        
        if form.is_valid():
            username = form.cleaned_data.get('username')
            password = form.cleaned_data.get('password')
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                login(request, user)
                messages.success(request, f'Welcome back, {username}!')
                
                # Clear rate limit on successful login
                ip_address = get_client_ip(request)
                RateLimitManager.clear_rate_limit(ip_address, 'login')
                
                # Redirect to next page or dashboard
                next_page = request.GET.get('next', 'dashboard')
                return redirect(next_page)
            else:
                messages.error(request, 'Invalid username or password.')
        else:
            messages.error(request, 'Invalid form data.')
    else:
        form = AuthenticationForm()
    
    return render(request, 'ip_tracking/login.html', {'form': form})


# Registration view with rate limiting
@csrf_protect
@require_http_methods(["GET", "POST"])
@rate_limit_decorator(limit='2/minute', key='register', method='POST')
def register_view(request):
    """
    User registration view with rate limiting.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = UserCreationForm(request.POST)
        
        if form.is_valid():
            user = form.save()
            login(request, user)
            messages.success(request, 'Registration successful!')
            
            # Clear rate limit on successful registration
            ip_address = get_client_ip(request)
            RateLimitManager.clear_rate_limit(ip_address, 'register')
            
            return redirect('dashboard')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = UserCreationForm()
    
    return render(request, 'ip_tracking/register.html', {'form': form})


# Password reset view with rate limiting
@csrf_protect
@require_http_methods(["GET", "POST"])
@rate_limit_decorator(limit='2/minute', key='password_reset', method='POST')
def password_reset_view(request):
    """
    Password reset view with rate limiting.
    """
    if request.user.is_authenticated:
        return redirect('dashboard')
    
    if request.method == 'POST':
        form = PasswordResetForm(request.POST)
        
        if form.is_valid():
            form.save(
                request=request,
                use_https=request.is_secure(),
                from_email=None,
                email_template_name='registration/password_reset_email.html',
                subject_template_name='registration/password_reset_subject.txt'
            )
            messages.success(request, 'Password reset email sent!')
            
            # Clear rate limit on successful submission
            ip_address = get_client_ip(request)
            RateLimitManager.clear_rate_limit(ip_address, 'password_reset')
            
            return redirect('login')
        else:
            messages.error(request, 'Invalid email address.')
    else:
        form = PasswordResetForm()
    
    return render(request, 'ip_tracking/password_reset.html', {'form': form})


# API view with different rate limits for authenticated vs anonymous
@require_http_methods(["GET", "POST"])
def api_view(request):
    """
    API view with different rate limits based on authentication status.
    """
    ip_address = get_client_ip(request)
    
    if request.user.is_authenticated:
        # Authenticated users: 10 requests per minute
        limit = '10/minute'
        key = 'api_authenticated'
    else:
        # Anonymous users: 5 requests per minute
        limit = '5/minute'
        key = 'api_anonymous'
    
    # Apply rate limiting
    is_limited, remaining, reset_time = RateLimitManager.is_rate_limited(
        ip_address, key, *RateLimitManager.parse_limit_string(limit)
    )
    
    if is_limited:
        return JsonResponse({
            'error': 'Rate limit exceeded',
            'retry_after': int(reset_time - time.time()),
            'limit': limit,
            'remaining': 0,
        }, status=429)
    
    # Process API request
    data = {
        'message': 'API request successful',
        'remaining_requests': remaining,
        'rate_limit': limit,
        'authenticated': request.user.is_authenticated,
    }
    
    response = JsonResponse(data)
    
    # Add rate limit headers
    response_headers = RateLimitManager.get_rate_limit_headers(
        ip_address, key, *RateLimitManager.parse_limit_string(limit)
    )
    
    for header, value in response_headers.items():
        response[header] = value
    
    return response


# Rate limit exceeded view
def rate_limit_exceeded(request, exception=None):
    """
    Custom view for rate limit exceeded errors.
    """
    context = {
        'title': 'Rate Limit Exceeded',
        'message': 'Too many requests from your IP address.',
        'status_code': 429,
        'ip_address': get_client_ip(request),
    }
    
    return render(request, 'ip_tracking/rate_limit_exceeded.html', context, status=429)


# Admin view to manage rate limits
@login_required
@require_http_methods(["GET", "POST"])
def rate_limit_admin(request):
    """
    Admin view to manage rate limits and blocked IPs.
    """
    if not request.user.is_staff:
        return HttpResponseForbidden("Access denied")
    
    from .models import RateLimit
    from django.core.paginator import Paginator
    
    # Get filter parameters
    ip_filter = request.GET.get('ip', '')
    key_filter = request.GET.get('key', '')
    blocked_only = request.GET.get('blocked', '')
    
    # Build query
    query = RateLimit.objects.all()
    
    if ip_filter:
        query = query.filter(ip_address__contains=ip_filter)
    
    if key_filter:
        query = query.filter(key__contains=key_filter)
    
    if blocked_only:
        query = query.filter(is_blocked=True)
    
    # Pagination
    paginator = Paginator(query.order_by('-created_at'), 20)
    page = request.GET.get('page', 1)
    rate_limits = paginator.get_page(page)
    
    # Handle actions
    if request.method == 'POST':
        action = request.POST.get('action')
        rate_limit_id = request.POST.get('rate_limit_id')
        
        try:
            rate_limit = RateLimit.objects.get(id=rate_limit_id)
            
            if action == 'unblock':
                rate_limit.unblock()
                messages.success(request, f'Unblocked IP {rate_limit.ip_address}')
            elif action == 'clear':
                RateLimitManager.clear_rate_limit(rate_limit.ip_address, rate_limit.key)
                rate_limit.delete()
                messages.success(request, f'Cleared rate limit for IP {rate_limit.ip_address}')
            elif action == 'block':
                duration = int(request.POST.get('duration', 3600))
                reason = request.POST.get('reason', '')
                rate_limit.block(duration, reason)
                messages.success(request, f'Blocked IP {rate_limit.ip_address} for {duration} seconds')
        
        except RateLimit.DoesNotExist:
            messages.error(request, 'Rate limit record not found')
    
    # Get statistics
    stats = RateLimitManager.get_rate_limit_stats()
    
    context = {
        'rate_limits': rate_limits,
        'stats': stats,
        'ip_filter': ip_filter,
        'key_filter': key_filter,
        'blocked_only': blocked_only,
    }
    
    return render(request, 'ip_tracking/rate_limit_admin.html', context)


# Class-based view with rate limiting
@method_decorator(ratelimit(key='ip', rate='10/minute', method='POST'), name='post')
class SensitiveView(View):
    """
    Class-based view with rate limiting.
    """
    
    def get(self, request):
        return render(request, 'ip_tracking/sensitive.html')
    
    def post(self, request):
        # Check rate limit
        if getattr(request, 'limited', False):
            return JsonResponse({
                'error': 'Rate limit exceeded',
                'retry_after': request.ratelimit['remaining'],
            }, status=429)
        
        # Process sensitive operation
        # ...
        
        return JsonResponse({'success': True})
