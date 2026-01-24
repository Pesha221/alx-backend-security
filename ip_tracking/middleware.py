# ip_tracking/middleware.py
import time
import logging
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from django.conf import settings
from django.http import JsonResponse
from django.shortcuts import render
from ipware import get_client_ip
from user_agents import parse

logger = logging.getLogger(__name__)

class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, and metadata of every request.
    """
    def __call__(self, request):
        start_time = time.time()
        response = self.get_response(request)
        response_time = time.time() - start_time
        
        self._log_request(request, response, response_time)
        return response

    def _log_request(self, request, response, response_time):
        try:
            # Import inside method to avoid early app-loading conflicts
            from .models import RequestLog

            client_ip, _ = get_client_ip(request)
            if not client_ip:
                return

            user_agent_string = request.META.get("HTTP_USER_AGENT", "")
            user_agent = parse(user_agent_string)
            
            # Using the renamed fields confirmed in your migration
            RequestLog.objects.create(
                ip_address=client_ip,
                path=request.path[:255],
                method=request.method,
                user=request.user if request.user.is_authenticated else None,
                user_agent=user_agent_string,
                status_code=response.status_code,
                response_time=response_time,
                is_hosting=user_agent.is_bot,    # Renamed from is_bot
                is_proxy=user_agent.is_mobile,   # Renamed from is_mobile
                is_tor=user_agent.is_pc,         # Renamed from is_pc
                is_vpn=user_agent.is_tablet,     # Renamed from is_tablet
                timestamp=timezone.now(),
            )
        except Exception as e:
            logger.error(f"IP Tracking Middleware Error: {e}")

class IPBlockingMiddleware(MiddlewareMixin):
    """
    Middleware to block requests from blacklisted IP addresses.
    """
    def __call__(self, request):
        from .models import BlockedIP
        client_ip, _ = get_client_ip(request)
        
        # Check if IP exists in BlockedIP table
        if BlockedIP.objects.filter(ip_address=client_ip).exists():
            if request.path.startswith('/api/'):
                return JsonResponse({'error': 'Access Denied', 'ip': client_ip}, status=403)
            
            # Returns the custom blocked.html template
            return render(request, 'ip_tracking/blocked.html', {'ip': client_ip}, status=403)
            
        return self.get_response(request)
