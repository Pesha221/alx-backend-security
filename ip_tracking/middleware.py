# ip_tracking/middleware.py
import time
from django.utils.deprecation import MiddlewareMixin
from django.utils import timezone
from ipware import get_client_ip
from user_agents import parse


class IPLoggingMiddleware(MiddlewareMixin):
    """
    Middleware to log IP address, timestamp, and path of every incoming request.
    """

    def __init__(self, get_response):
        self.get_response = get_response
        super().__init__(get_response)

    def __call__(self, request):
        # Start timer to measure response time
        start_time = time.time()

        # Process the request (get response)
        response = self.get_response(request)

        # Calculate response time
        response_time = time.time() - start_time

        # Log the request
        self._log_request(request, response, response_time)

        return response

    def _log_request(self, request, response, response_time):
        """
        Log request details to database.
        """
        try:
            # Get client IP address
            client_ip, is_routable = get_client_ip(request)

            # Skip if no IP found (shouldn't happen)
            if not client_ip:
                return

            # Parse user agent
            user_agent_string = request.META.get("HTTP_USER_AGENT", "")
            user_agent = parse(user_agent_string)

            # Extract query string (if any)
            query_string = request.META.get("QUERY_STRING", "")

            # Get referer
            referer = request.META.get("HTTP_REFERER", "")

            # Get content type from response
            content_type = (
                response.get("Content-Type", "").split(";")[0]
                if response.get("Content-Type")
                else ""
            )

            # Create request log entry
            from .models import RequestLog

            RequestLog.objects.create(
                ip_address=client_ip,
                path=request.path,
                method=request.method,
                query_string=query_string,
                user=request.user if request.user.is_authenticated else None,
                user_agent=user_agent_string,
                is_mobile=user_agent.is_mobile,
                is_tablet=user_agent.is_tablet,
                is_touch_capable=user_agent.is_touch_capable,
                is_pc=user_agent.is_pc,
                is_bot=user_agent.is_bot,
                browser=user_agent.browser.family,
                browser_version=user_agent.browser.version_string,
                os=user_agent.os.family,
                os_version=user_agent.os.version_string,
                device=user_agent.device.family,
                status_code=response.status_code,
                response_size=(
                    len(response.content) if hasattr(response, "content") else None
                ),
                response_time=response_time,
                referer=referer,
                content_type=content_type,
                timestamp=timezone.now(),
            )

        except Exception as e:
            # Log error but don't break the request
            import logging

            logger = logging.getLogger(__name__)
            logger.error(f"Error logging request: {e}")


class SimpleIPLoggingMiddleware(MiddlewareMixin):
    """
    Simplified version that only logs IP, timestamp, and path.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Process request and get response
        response = self.get_response(request)

        # Log basic information
        self._log_basic_info(request, response)

        return response

    def _log_basic_info(self, request, response):
        """
        Log only IP, timestamp, and path.
        """
        try:
            # Get client IP address using Django's built-in method
            x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
            if x_forwarded_for:
                client_ip = x_forwarded_for.split(",")[0]
            else:
                client_ip = request.META.get("REMOTE_ADDR")

            # Skip if no IP found
            if not client_ip:
                return

            from .models import RequestLog

            RequestLog.objects.create(
                ip_address=client_ip,
                path=request.path,
                method=request.method,
                timestamp=timezone.now(),
            )

        except Exception as e:
            # Silently fail for logging errors
            pass

# ip_tracking/middleware.py
import time
import logging
from django.utils.deprecation import MiddlewareMixin
from django.core.cache import cache
from .models import RequestLog
from .geolocation import IPGeolocationService
from django.conf import settings

logger = logging.getLogger(__name__)

class IPTrackingMiddleware(MiddlewareMixin):
    """
    Middleware for tracking IP addresses with geolocation.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
    
    def __call__(self, request):
        # Start timer
        start_time = time.time()
        
        # Process request
        response = self.get_response(request)
        
        # Calculate response time
        response_time = time.time() - start_time
        
        # Log the request
        self._log_request(request, response, response_time)
        
        return response
    
    def _log_request(self, request, response, response_time):
        """
        Log request details with geolocation.
        """
        try:
            # Skip logging for certain paths (optional)
            skip_paths = getattr(settings, 'IP_TRACKING_SKIP_PATHS', [
                '/admin/', 
                '/static/', 
                '/media/',
                '/favicon.ico',
            ])
            
            if any(request.path.startswith(path) for path in skip_paths):
                return
            
            # Get IP address
            ip = self._get_client_ip(request)
            
            # Get geolocation data (with caching)
            geolocation_data = IPGeolocationService.get_geolocation(ip)
            
            # Create log entry
            log_entry = RequestLog.objects.create(
                ip_address=ip,
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                path=request.path,
                method=request.method,
                status_code=response.status_code,
                response_time=response_time,
                referer=request.META.get('HTTP_REFERER', ''),
                query_string=request.META.get('QUERY_STRING', ''),
                content_type=response.get('Content-Type', ''),
                user=request.user if request.user.is_authenticated else None,
            )
            
            # Save geolocation data if available
            if geolocation_data:
                log_entry.save_geolocation_data(geolocation_data)
            
            # Log to console for debugging
            if getattr(settings, 'IP_TRACKING_DEBUG', False):
                logger.info(
                    f"Request: {request.method} {request.path} "
                    f"from {ip} ({geolocation_data.get('country', 'Unknown')}) "
                    f"in {response_time:.3f}s"
                )
        
        except Exception as e:
            logger.error(f"Error logging request: {e}")
    
    def _get_client_ip(self, request):
        """
        Get the real client IP address.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        
        if x_forwarded_for:
            # Get the first IP in the list
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        
        return ip
    
    def process_exception(self, request, exception):
        """
        Log exceptions with geolocation data.
        """
        try:
            ip = self._get_client_ip(request)
            geolocation_data = IPGeolocationService.get_geolocation(ip)
            
            logger.error(
                f"Exception for {request.method} {request.path} "
                f"from {ip} ({geolocation_data.get('country', 'Unknown')}): "
                f"{exception}"
            )
        except Exception as e:
            logger.error(f"Error logging exception: {e}")

# ip_tracking/middleware.py
import time
import logging
from django.utils.deprecation import MiddlewareMixin
from django.http import HttpResponseForbidden, JsonResponse
from django.shortcuts import render
from django.conf import settings
from .models import BlockedIP, RequestLog
from .geolocation import IPGeolocationService

logger = logging.getLogger(__name__)

class IPBlockingMiddleware(MiddlewareMixin):
    """
    Middleware to block requests from blacklisted IP addresses.
    """
    
    def __init__(self, get_response):
        super().__init__(get_response)
        self.get_response = get_response
        self.blocking_enabled = getattr(settings, 'IP_BLOCKING_ENABLED', True)
    
    def __call__(self, request):
        # Skip IP blocking for certain paths (optional)
        skip_paths = getattr(settings, 'IP_BLOCKING_SKIP_PATHS', [
            '/admin/',
            '/health/',
            '/robots.txt',
            '/favicon.ico',
        ])
        
        if any(request.path.startswith(path) for path in skip_paths):
            return self.get_response(request)
        
        # Get client IP address
        ip_address = self._get_client_ip(request)
        
        # Check if IP is blocked
        blocked_ip = BlockedIP.is_ip_blocked(ip_address)
        
        if blocked_ip and self.blocking_enabled:
            # Log the blocked request
            self._log_blocked_request(request, ip_address, blocked_ip)
            
            # Return 403 Forbidden response
            return self._blocked_response(request, ip_address, blocked_ip)
        
        # Process request normally
        response = self.get_response(request)
        
        # Log request (optional, for tracking)
        self._log_request(request, response, ip_address)
        
        return response
    
    def _get_client_ip(self, request):
        """
        Get the real client IP address.
        Handles proxies and load balancers.
        """
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        
        if x_forwarded_for:
            # Get the first IP in the list (client IP)
            ip = x_forwarded_for.split(',')[0].strip()
        else:
            ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
        
        return ip
    
    def _log_blocked_request(self, request, ip_address, blocked_ip):
        """Log blocked request for monitoring"""
        try:
            # Get geolocation data for logging
            geolocation_data = IPGeolocationService.get_geolocation(ip_address)
            
            logger.warning(
                f"BLOCKED REQUEST: IP {ip_address} "
                f"({geolocation_data.get('country', 'Unknown')}) "
                f"tried to access {request.method} {request.path} "
                f"from {request.META.get('HTTP_USER_AGENT', 'Unknown')}. "
                f"Block reason: {blocked_ip.reason}. "
                f"Block type: {blocked_ip.get_block_type_display()}"
            )
            
            # Increment request count on blocked IP
            blocked_ip.request_count += 1
            
            # Update accessed paths
            if request.path not in blocked_ip.accessed_paths:
                blocked_ip.accessed_paths.append(request.path)
                blocked_ip.accessed_paths = blocked_ip.accessed_paths[:50]  # Keep last 50
            
            # Update user agents
            user_agent = request.META.get('HTTP_USER_AGENT')
            if user_agent and user_agent not in blocked_ip.user_agents:
                blocked_ip.user_agents.append(user_agent)
                blocked_ip.user_agents = blocked_ip.user_agents[:20]  # Keep last 20
            
            blocked_ip.save()
            
        except Exception as e:
            logger.error(f"Error logging blocked request: {e}")
    
    def _log_request(self, request, response, ip_address):
        """Log normal request for analysis"""
        try:
            # Optional: Log all requests to RequestLog model
            if getattr(settings, 'IP_TRACKING_ENABLED', False):
                RequestLog.objects.create(
                    ip_address=ip_address,
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    path=request.path,
                    method=request.method,
                    status_code=response.status_code,
                    response_time=0,  # You can calculate this if needed
                )
        except Exception as e:
            logger.error(f"Error logging request: {e}")
    
    def _blocked_response(self, request, ip_address, blocked_ip):
        """
        Return appropriate blocked response based on request type.
        """
        # Prepare context
        context = {
            'ip_address': ip_address,
            'block_reason': blocked_ip.reason,
            'block_type': blocked_ip.get_block_type_display(),
            'blocked_at': blocked_ip.blocked_at,
            'blocked_until': blocked_ip.blocked_until,
            'is_permanent': blocked_ip.is_permanent,
            'time_remaining': blocked_ip.time_remaining,
            'display_duration': blocked_ip.display_duration,
        }
        
        # Add geolocation info if available
        geolocation_data = IPGeolocationService.get_geolocation(ip_address)
        if geolocation_data:
            context.update({
                'country': geolocation_data.get('country'),
                'city': geolocation_data.get('city'),
                'isp': geolocation_data.get('isp'),
            })
        
        # Return JSON for API requests
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest' or \
           request.content_type == 'application/json' or \
           request.path.startswith('/api/'):
            
            response_data = {
                'error': 'Access Denied',
                'message': 'Your IP address has been blocked.',
                'ip_address': ip_address,
                'reason': blocked_ip.reason,
                'block_type': blocked_ip.get_block_type_display(),
                'status_code': 403,
            }
            
            if not blocked_ip.is_permanent and blocked_ip.time_remaining:
                response_data['retry_after'] = blocked_ip.time_remaining
            
            response = JsonResponse(response_data, status=403)
            
        else:
            # Return HTML page for browser requests
            template_name = getattr(settings, 'IP_BLOCK_TEMPLATE', 'ip_tracking/blocked.html')
            response = render(request, template_name, context, status=403)
        
        # Add security headers
        response['X-IP-Blocked'] = 'true'
        response['X-IP-Block-Reason'] = blocked_ip.reason
        
        if not blocked_ip.is_permanent and blocked_ip.time_remaining:
            response['Retry-After'] = str(blocked_ip.time_remaining)
        
        return response
    
    def process_exception(self, request, exception):
        """Handle exceptions in middleware"""
        logger.error(f"IP Blocking Middleware Exception: {exception}")
        return None
