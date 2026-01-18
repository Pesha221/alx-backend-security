# ip_tracking/ratelimit_utils.py
import time
from django.core.cache import cache
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import logging
from .models import RateLimit

logger = logging.getLogger(__name__)

class RateLimitManager:
    """
    Custom rate limiting manager with IP-based tracking.
    """
    
    @staticmethod
    def is_rate_limited(ip_address, key, limit, period, increment=True):
        """
        Check if IP address is rate limited.
        
        Args:
            ip_address: Client IP address
            key: Rate limit key (e.g., 'login', 'api')
            limit: Maximum requests allowed
            period: Time period in seconds
            increment: Whether to increment the count
            
        Returns:
            Tuple of (is_limited, remaining, reset_time)
        """
        # Check if rate limiting is disabled
        if not getattr(settings, 'RATELIMIT_ENABLE', True):
            return False, limit, None
        
        # Create cache key
        cache_key = f"ratelimit:{key}:{ip_address}"
        
        # Get current count
        current_count = cache.get(cache_key, 0)
        
        # Check if blocked in database
        try:
            rate_limit = RateLimit.objects.filter(
                ip_address=ip_address,
                key=key,
                is_blocked=True
            ).first()
            
            if rate_limit and rate_limit.is_currently_blocked:
                logger.warning(f"IP {ip_address} is blocked for {key}")
                return True, 0, rate_limit.blocked_until
        except Exception as e:
            logger.error(f"Error checking rate limit block: {e}")
        
        # Check if limit exceeded
        if current_count >= limit:
            # Record violation
            try:
                rate_limit_record = RateLimit.get_or_create_for_ip(
                    ip_address, key, limit, period
                )
                rate_limit_record.record_violation()
                
                # Check if should be blocked
                if (rate_limit_record.violation_count >= 
                    getattr(settings, 'IP_BLOCKING', {}).get('MAX_ATTEMPTS', 10)):
                    block_duration = getattr(settings, 'IP_BLOCKING', {}).get('BLOCK_DURATION', 3600)
                    rate_limit_record.block(block_duration, "Too many rate limit violations")
                    logger.warning(f"Blocked IP {ip_address} for {block_duration} seconds")
            except Exception as e:
                logger.error(f"Error recording rate limit violation: {e}")
            
            # Calculate reset time
            reset_time = time.time() + period
            return True, 0, reset_time
        
        # Increment count if requested
        if increment:
            cache.set(cache_key, current_count + 1, period)
        
        # Calculate remaining requests and reset time
        remaining = max(0, limit - (current_count + 1) if increment else limit - current_count)
        reset_time = time.time() + period
        
        return False, remaining, reset_time
    
    @staticmethod
    def get_rate_limit_headers(ip_address, key, limit, period):
        """
        Get rate limit headers for response.
        
        Returns:
            Dictionary of rate limit headers
        """
        is_limited, remaining, reset_time = RateLimitManager.is_rate_limited(
            ip_address, key, limit, period, increment=False
        )
        
        headers = {}
        
        if getattr(settings, 'SECURE_RATE_LIMITING', {}).get('ENABLE_X_RATELIMIT_HEADERS', True):
            limit_header = settings.SECURE_RATE_LIMITING.get('X_RATELIMIT_LIMIT', 'X-RateLimit-Limit')
            remaining_header = settings.SECURE_RATE_LIMITING.get('X_RATELIMIT_REMAINING', 'X-RateLimit-Remaining')
            reset_header = settings.SECURE_RATE_LIMITING.get('X_RATELIMIT_RESET', 'X-RateLimit-Reset')
            
            headers[limit_header] = str(limit)
            headers[remaining_header] = str(remaining)
            headers[reset_header] = str(int(reset_time)) if reset_time else str(int(time.time() + period))
        
        return headers
    
    @staticmethod
    def clear_rate_limit(ip_address, key=None):
        """
        Clear rate limit for an IP address.
        
        Args:
            ip_address: IP address to clear
            key: Specific rate limit key (clear all if None)
        """
        if key:
            cache_keys = [f"ratelimit:{key}:{ip_address}"]
        else:
            # Get all keys for this IP
            cache_key_pattern = f"ratelimit:*:{ip_address}"
            cache_keys = cache.keys(cache_key_pattern)
        
        if cache_keys:
            cache.delete_many(cache_keys)
            logger.info(f"Cleared rate limit for IP {ip_address}")
    
    @staticmethod
    def get_rate_limit_stats(ip_address=None, key=None):
        """
        Get rate limiting statistics.
        
        Returns:
            Dictionary with rate limit statistics
        """
        stats = {
            'total_blocks': 0,
            'active_blocks': 0,
            'total_violations': 0,
            'top_offenders': [],
        }
        
        try:
            # Get blocked IPs
            blocked_query = RateLimit.objects.filter(is_blocked=True)
            
            if ip_address:
                blocked_query = blocked_query.filter(ip_address=ip_address)
            if key:
                blocked_query = blocked_query.filter(key=key)
            
            stats['total_blocks'] = blocked_query.count()
            stats['active_blocks'] = blocked_query.filter(
                blocked_until__gt=timezone.now()
            ).count()
            
            # Get violation statistics
            violations_query = RateLimit.objects.filter(violation_count__gt=0)
            
            if ip_address:
                violations_query = violations_query.filter(ip_address=ip_address)
            if key:
                violations_query = violations_query.filter(key=key)
            
            stats['total_violations'] = violations_query.aggregate(
                total=models.Sum('violation_count')
            )['total'] or 0
            
            # Get top offenders
            stats['top_offenders'] = list(
                violations_query.order_by('-violation_count')[:10].values(
                    'ip_address', 'key', 'violation_count', 'last_violation'
                )
            )
            
        except Exception as e:
            logger.error(f"Error getting rate limit stats: {e}")
        
        return stats


def get_client_ip(request):
    """
    Get client IP address from request.
    
    Args:
        request: Django HttpRequest object
        
    Returns:
        IP address string
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    
    if x_forwarded_for:
        # Get the first IP in the list
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')
    
    return ip


def rate_limit_decorator(limit='5/minute', key=None, method='POST', block=True):
    """
    Custom rate limit decorator.
    
    Args:
        limit: Rate limit string (e.g., '5/minute', '100/hour')
        key: Rate limit key
        method: HTTP method to apply rate limit to
        block: Whether to block IP on violation
        
    Returns:
        Decorator function
    """
    from functools import wraps
    
    def decorator(view_func):
        @wraps(view_func)
        def wrapped_view(request, *args, **kwargs):
            # Only apply to specified method
            if request.method != method:
                return view_func(request, *args, **kwargs)
            
            # Get client IP
            ip_address = get_client_ip(request)
            
            # Parse limit string
            limit_value, period_str = limit.split('/')
            limit_value = int(limit_value)
            
            # Convert period to seconds
            period_map = {
                'second': 1,
                'minute': 60,
                'hour': 3600,
                'day': 86400,
            }
            
            period = period_map.get(period_str.lower(), 60)
            
            # Use view name as key if not specified
            if not key:
                key_name = f"{view_func.__module__}.{view_func.__name__}"
            else:
                key_name = key
            
            # Check rate limit
            is_limited, remaining, reset_time = RateLimitManager.is_rate_limited(
                ip_address, key_name, limit_value, period
            )
            
            if is_limited:
                from django.http import JsonResponse
                from django.shortcuts import render
                
                # Add rate limit headers
                response_headers = RateLimitManager.get_rate_limit_headers(
                    ip_address, key_name, limit_value, period
                )
                
                # Return appropriate response
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    response = JsonResponse({
                        'error': 'Rate limit exceeded',
                        'retry_after': int(reset_time - time.time()),
                        'limit': limit,
                        'remaining': 0,
                    }, status=429)
                else:
                    context = {
                        'limit': limit,
                        'retry_after': int(reset_time - time.time()),
                        'ip_address': ip_address,
                        'key': key_name,
                    }
                    response = render(request, 'ip_tracking/rate_limit_exceeded.html', context)
                    response.status_code = 429
                
                # Add headers
                for header, value in response_headers.items():
                    response[header] = value
                
                return response
            
            # Call original view
            response = view_func(request, *args, **kwargs)
            
            # Add rate limit headers to successful response
            response_headers = RateLimitManager.get_rate_limit_headers(
                ip_address, key_name, limit_value, period
            )
            
            for header, value in response_headers.items():
                response[header] = value
            
            return response
        
        return wrapped_view
    
    return decorator
