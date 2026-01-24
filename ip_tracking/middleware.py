
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
            
            # Using the NEW field names confirmed in your migration
            log_entry = RequestLog.objects.create(
                ip_address=client_ip,
                path=request.path,
                method=request.method,
                user=request.user if request.user.is_authenticated else None,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                is_hosting=user_agent.is_bot,  # Renamed from is_bot
                is_proxy=user_agent.is_mobile, # Renamed from is_mobile
                is_tor=user_agent.is_pc,       # Renamed from is_pc
                is_vpn=user_agent.is_tablet,   # Renamed from is_tablet
                status_code=response.status_code,
                response_time=response_time,
                timestamp=timezone.now(),
            )
            
            geo_data = IPGeolocationService.get_geolocation(client_ip)
            if geo_data:
                log_entry.save_geolocation_data(geo_data)

        except Exception as e:
            logger.error(f"Error in IPTrackingMiddleware: {e}")

class IPBlockingMiddleware(MiddlewareMixin):
    def __call__(self, request):
        from .models import BlockedIP
        client_ip, _ = get_client_ip(request)
        blocked_ip = BlockedIP.is_ip_blocked(client_ip)
        
        if blocked_ip and getattr(settings, 'IP_BLOCKING_ENABLED', True):
            if request.path.startswith('/api/') or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({'error': 'Access Denied', 'reason': blocked_ip.reason}, status=403)
            
            template = getattr(settings, 'IP_BLOCK_TEMPLATE', 'ip_tracking/blocked.html')
            return render(request, template, {'ip_address': client_ip, 'block_reason': blocked_ip.reason}, status=403)
            
        return self.get_response(request)
