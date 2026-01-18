# ip_tracking/admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import RequestLog

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address_display',
        'path_short',
        'method_display',
        'user_display',
        'timestamp_short',
        'status_code_display',
        'response_time_display',
        'is_mobile_display',
    ]
    
    list_filter = [
        'method',
        'status_code',
        'timestamp',
        'is_mobile',
        'is_bot',
        'country',
    ]
    
    search_fields = [
        'ip_address',
        'path',
        'user__username',
        'user_agent',
    ]
    
    readonly_fields = [
        'ip_address',
        'path',
        'method',
        'timestamp',
        'response_time',
        'user_agent_full',
        'device_info',
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('ip_address', 'path', 'method', 'timestamp', 'response_time')
        }),
        ('User Information', {
            'fields': ('user', 'country', 'city', 'region'),
            'classes': ('collapse',)
        }),
        ('Device Information', {
            'fields': ('user_agent_full', 'device_info', 'is_mobile', 'is_tablet', 'is_bot'),
            'classes': ('collapse',)
        }),
        ('Response Information', {
            'fields': ('status_code', 'response_size', 'content_type', 'referer'),
            'classes': ('collapse',)
        }),
    )
    
    def ip_address_display(self, obj):
        """Display IP address with color coding"""
        color = '#2ecc71' if not obj.is_bot else '#e74c3c'  # Green for humans, red for bots
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.ip_address
        )
    ip_address_display.short_description = 'IP Address'
    ip_address_display.admin_order_field = 'ip_address'
    
    def path_short(self, obj):
        """Display shortened path"""
        if len(obj.path) > 50:
            return obj.path[:50] + '...'
        return obj.path
    path_short.short_description = 'Path'
    path_short.admin_order_field = 'path'
    
    def method_display(self, obj):
        """Color-coded HTTP method"""
        colors = {
            'GET': '#3498db',
            'POST': '#2ecc71',
            'PUT': '#f39c12',
            'DELETE': '#e74c3c',
            'PATCH': '#9b59b6',
        }
        color = colors.get(obj.method, '#7f8c8d')
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.method
        )
    method_display.short_description = 'Method'
    method_display.admin_order_field = 'method'
    
    def user_display(self, obj):
        """Display user with link if authenticated"""
        if obj.user:
            return format_html(
                '<a href="/admin/auth/user/{}/change/">{}</a>',
                obj.user.id,
                obj.user.username
            )
        return 'Anonymous'
    user_display.short_description = 'User'
    
    def timestamp_short(self, obj):
        """Display short timestamp"""
        return obj.timestamp.strftime('%H:%M:%S')
    timestamp_short.short_description = 'Time'
    timestamp_short.admin_order_field = 'timestamp'
    
    def status_code_display(self, obj):
        """Color-coded status code"""
        if 200 <= obj.status_code < 300:
            color = '#2ecc71'
        elif 300 <= obj.status_code < 400:
            color = '#3498db'
        elif 400 <= obj.status_code < 500:
            color = '#f39c12'
        else:
            color = '#e74c3c'
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color,
            obj.status_code or 'N/A'
        )
    status_code_display.short_description = 'Status'
    status_code_display.admin_order_field = 'status_code'
    
    def response_time_display(self, obj):
        """Display response time with color coding"""
        if not obj.response_time:
            return 'N/A'
        
        if obj.response_time < 0.5:
            color = '#2ecc71'
            status = 'Fast'
        elif obj.response_time < 2:
            color = '#f39c12'
            status = 'Medium'
        else:
            color = '#e74c3c'
            status = 'Slow'
        
        return format_html(
            '<span style="color: {};" title="{}">{:.3f}s</span>',
            color,
            status,
            obj.response_time
        )
    response_time_display.short_description = 'Time'
    response_time_display.admin_order_field = 'response_time'
    
    def is_mobile_display(self, obj):
        """Display mobile status"""
        if obj.is_mobile:
            return '📱 Mobile'
        elif obj.is_tablet:
            return '📱 Tablet'
        elif obj.is_pc:
            return '💻 PC'
        else:
            return '❓ Unknown'
    is_mobile_display.short_description = 'Device'
    
    def user_agent_full(self, obj):
        """Display full user agent"""
        return obj.user_agent
    user_agent_full.short_description = 'User Agent'
    
    def device_info(self, obj):
        """Display device information"""
        info = []
        if obj.browser:
            info.append(f"Browser: {obj.browser} {obj.browser_version}")
        if obj.os:
            info.append(f"OS: {obj.os} {obj.os_version}")
        if obj.device:
            info.append(f"Device: {obj.device}")
        
        return '\n'.join(info)
    device_info.short_description = 'Device Details'
    
    # Admin actions
    actions = ['export_as_csv', 'delete_old_logs']
    
    def export_as_csv(self, request, queryset):
        """Export selected logs as CSV"""
        import csv
        from django.http import HttpResponse
        from io import StringIO
        
        f = StringIO()
        writer = csv.writer(f)
        
        # Write headers
        writer.writerow([
            'IP Address', 'Path', 'Method', 'User', 'Timestamp',
            'Status Code', 'Response Time', 'User Agent', 'Country'
        ])
        
        # Write data
        for log in queryset:
            writer.writerow([
                log.ip_address,
                log.path,
                log.method,
                log.user.username if log.user else 'Anonymous',
                log.timestamp.isoformat(),
                log.status_code,
                log.response_time,
                log.user_agent[:100],  # Truncate long user agents
                log.country or 'Unknown',
            ])
        
        f.seek(0)
        response = HttpResponse(f, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=request_logs.csv'
        return response
    export_as_csv.short_description = "Export selected logs as CSV"
    
    def delete_old_logs(self, request, queryset):
        """Delete logs older than 30 days"""
        from django.utils import timezone
        from datetime import timedelta
        
        thirty_days_ago = timezone.now() - timedelta(days=30)
        old_logs = RequestLog.objects.filter(timestamp__lt=thirty_days_ago)
        count = old_logs.count()
        old_logs.delete()
        
        self.message_user(request, f"Deleted {count} logs older than 30 days")
    delete_old_logs.short_description = "Delete logs older than 30 days"

# ip_tracking/admin.py
from django.contrib import admin
from django.utils.html import format_html
from .models import RequestLog

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address',
        'country_flag',
        'location_summary',
        'path_short',
        'method',
        'status_code',
        'response_time_display',
        'timestamp_short',
        'is_suspicious_display',
    ]
    
    list_filter = [
        'country',
        'city',
        'method',
        'status_code',
        'is_vpn',
        'is_proxy',
        'is_tor',
        'is_hosting',
        'timestamp',
    ]
    
    search_fields = [
        'ip_address',
        'country',
        'city',
        'path',
        'user_agent',
    ]
    
    readonly_fields = [
        'ip_address',
        'user_agent',
        'path',
        'method',
        'status_code',
        'response_time',
        'timestamp',
        'location_summary',
        'is_suspicious',
        'raw_geolocation_data_preview',
    ]
    
    fieldsets = (
        ('Request Information', {
            'fields': (
                'ip_address',
                'path',
                'method',
                'status_code',
                'response_time',
                'timestamp',
            )
        }),
        ('Geolocation', {
            'fields': (
                'country',
                'city',
                'region',
                'latitude',
                'longitude',
                'timezone',
                'location_summary',
            )
        }),
        ('Network Information', {
            'fields': (
                'isp',
                'organization',
                'asn',
                'is_vpn',
                'is_proxy',
                'is_tor',
                'is_hosting',
                'is_suspicious',
            )
        }),
        ('Additional Data', {
            'fields': (
                'user_agent',
                'referer',
                'query_string',
                'content_type',
                'user',
                'raw_geolocation_data_preview',
            ),
            'classes': ('collapse',),
        }),
    )
    
    def country_flag(self, obj):
        """Display country with flag emoji"""
        if not obj.country_code:
            return "🌐"
        
        # Convert country code to flag emoji
        try:
            # Country code to regional indicator symbols
            code = obj.country_code.upper()
            if len(code) == 2:
                flag = ''.join(chr(ord(c) + 127397) for c in code)
                return format_html(f'{flag} {obj.country_code}')
        except:
            pass
        
        return obj.country_code or "🌐"
    country_flag.short_description = 'Country'
    
    def path_short(self, obj):
        """Display shortened path"""
        if len(obj.path) > 50:
            return obj.path[:50] + "..."
        return obj.path
    path_short.short_description = 'Path'
    
    def response_time_display(self, obj):
        """Format response time"""
        if obj.response_time < 1:
            color = "green"
        elif obj.response_time < 3:
            color = "orange"
        else:
            color = "red"
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{:.3f}s</span>',
            color,
            obj.response_time
        )
    response_time_display.short_description = 'Time'
    
    def timestamp_short(self, obj):
        """Format timestamp"""
        return obj.timestamp.strftime('%Y-%m-%d %H:%M')
    timestamp_short.short_description = 'Time'
    
    def is_suspicious_display(self, obj):
        """Display suspicious status"""
        if obj.is_suspicious:
            return format_html(
                '<span style="color: red; font-weight: bold;">⚠️ Suspicious</span>'
            )
        return format_html(
            '<span style="color: green;">✓ Normal</span>'
        )
    is_suspicious_display.short_description = 'Status'
    
    def raw_geolocation_data_preview(self, obj):
        """Display raw geolocation data"""
        if not obj.raw_geolocation_data:
            return "No raw data"
        
        import json
        formatted = json.dumps(obj.raw_geolocation_data, indent=2, ensure_ascii=False)
        return format_html('<pre style="max-height: 300px; overflow: auto;">{}</pre>', formatted)
    raw_geolocation_data_preview.short_description = 'Raw Geolocation Data'
    
    def has_add_permission(self, request):
        """Disable adding logs manually"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Disable editing logs"""
        return False

# ip_tracking/admin.py (add this admin class)
from django.contrib import admin
from django.utils.html import format_html
from django.urls import reverse
from .models import SuspiciousIP, AnomalyDetectionLog

@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address',
        'country_flag',
        'threat_level_badge',
        'reason_display',
        'severity_badge',
        'status_badge',
        'request_count',
        'first_detected',
        'is_currently_blocked_display',
    ]
    
    list_filter = [
        'severity',
        'status',
        'reason',
        'country',
        'is_vpn',
        'is_proxy',
        'is_tor',
        'auto_block',
        'first_detected',
    ]
    
    search_fields = [
        'ip_address',
        'country',
        'city',
        'isp',
        'reason',
        'investigation_notes',
    ]
    
    readonly_fields = [
        'ip_address',
        'first_detected',
        'last_detected',
        'request_count',
        'threat_level',
        'is_currently_blocked',
        'block_time_remaining',
        'user_agents_preview',
        'accessed_paths_preview',
        'threat_intelligence_preview',
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': (
                'ip_address',
                'country',
                'city',
                'isp',
                'first_detected',
                'last_detected',
            )
        }),
        ('Detection Details', {
            'fields': (
                'reason',
                'severity',
                'confidence_score',
                'detection_method',
                'request_count',
                'threat_level',
            )
        }),
        ('Network Information', {
            'fields': (
                'is_vpn',
                'is_proxy',
                'is_tor',
                'known_malicious',
                'known_botnet',
                'spamhaus_listed',
            )
        }),
        ('Status & Actions', {
            'fields': (
                'status',
                'auto_block',
                'is_currently_blocked',
                'block_time_remaining',
                'block_duration',
                'blocked_until',
                'investigator',
            )
        }),
        ('Investigation')
        , {
            'fields': (
                'investigation_notes',
                'user_agents_preview',
                'accessed_paths_preview',
                'threat_intelligence_preview',
            ),
            'classes': ('collapse',),
        }), 
