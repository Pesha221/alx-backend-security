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

# Import models inside methods to prevent "Model already registered" warnings during app init
logger = logging.getLogger(__name__)

class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware to log and track IP address geolocation and request details.
    """
    def __call__(self, request):
        start_time = time.time()
        response = self.get_response(request)
        response_time = time.time() - start_time
        
        self._log_request(request, response, response_time)
        return response

    def _log_request(self, request, response, response_time):
        try:
            from .models import RequestLog
            from .geolocation import IPGeolocationService

            client_ip, _ = get_client_ip(request)
            if not client_ip: return

            user_agent = parse(request.META.get("HTTP_USER_AGENT", ""))
            
            log_entry = RequestLog.objects.create(
                ip_address=client_ip,
                path=request.path,
                method=request.method,
                user=request.user if request.user.is_authenticated else None,
                user_agent=str(user_agent),
                status_code=response.status_code,
                response_time=response_time,
                timestamp=timezone.now(),
            )
            
            # Geolocation tracking
            geo_data = IPGeolocationService.get_geolocation(client_ip)
            if geo_data:
                log_entry.save_geolocation_data(geo_data)

        except Exception as e:
            logger.error(f"Error in IPTrackingMiddleware: {e}")

class IPBlockingMiddleware(MiddlewareMixin):
    """
    Middleware to block requests from blacklisted IP addresses.
    """
    def __call__(self, request):
        from .models import BlockedIP
        
        client_ip, _ = get_client_ip(request)
        blocked_ip = BlockedIP.is_ip_blocked(client_ip)
        
        if blocked_ip and getattr(settings, 'IP_BLOCKING_ENABLED', True):
            return self._blocked_response(request, client_ip, blocked_ip)
            
        return self.get_response(request)

    def _blocked_response(self, request, ip, blocked_ip):
        if request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({'error': 'Access Denied', 'reason': blocked_ip.reason}, status=403)
        
        template = getattr(settings, 'IP_BLOCK_TEMPLATE', 'ip_tracking/blocked.html')
        return render(request, template, {'ip': ip, 'reason': blocked_ip.reason}, status=403)
