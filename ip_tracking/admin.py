import csv
import json
from io import StringIO
from datetime import timedelta

from django.contrib import admin
from django.utils import timezone
from django.utils.html import format_html
from django.http import HttpResponse

from .models import RequestLog, SuspiciousIP, AnomalyDetectionLog

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    # Combined display showing security status and visual formatting
    list_display = [
        'ip_address_display',
        'country_flag',
        'path_short',
        'method_display',
        'status_code_display',
        'response_time_display',
        'timestamp_short',
        'is_suspicious_display',
        'user_display',
    ]
    
    list_filter = [
        'method',
        'status_code',
        'is_suspicious',
        'is_vpn',
        'is_bot',
        'country',
        'timestamp',
    ]
    
    search_fields = [
        'ip_address',
        'path',
        'user__username',
        'user_agent',
        'country',
    ]
    
    readonly_fields = [
        'ip_address',
        'path',
        'method',
        'timestamp',
        'response_time',
        'user_agent',
        'location_summary',
        'is_suspicious',
        'raw_geolocation_data_preview',
    ]
    
    fieldsets = (
        ('Basic Information', {
            'fields': ('ip_address', 'path', 'method', 'timestamp', 'status_code', 'response_time')
        }),
        ('Security & Network', {
            'fields': ('is_suspicious', 'is_vpn', 'is_proxy', 'is_tor', 'is_bot', 'isp', 'organization'),
        }),
        ('Geolocation', {
            'fields': ('country', 'city', 'region', 'latitude', 'longitude', 'timezone', 'location_summary'),
        }),
        ('User & Device', {
            'fields': ('user', 'user_agent', 'referer', 'raw_geolocation_data_preview'),
            'classes': ('collapse',)
        }),
    )

    # --- Formatting Methods ---

    def ip_address_display(self, obj):
        color = '#2ecc71' if not (obj.is_bot or obj.is_suspicious) else '#e74c3c'
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.ip_address)
    ip_address_display.short_description = 'IP Address'

    def country_flag(self, obj):
        if not hasattr(obj, 'country_code') or not obj.country_code:
            return "🌐"
        try:
            code = obj.country_code.upper()
            flag = ''.join(chr(ord(c) + 127397) for c in code)
            return format_html(f'{flag} {code}')
        except:
            return obj.country_code or "🌐"
    country_flag.short_description = 'Country'

    def method_display(self, obj):
        colors = {'GET': '#3498db', 'POST': '#2ecc71', 'PUT': '#f39c12', 'DELETE': '#e74c3c', 'PATCH': '#9b59b6'}
        color = colors.get(obj.method, '#7f8c8d')
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.method)
    method_display.short_description = 'Method'

    def status_code_display(self, obj):
        if 200 <= obj.status_code < 300: color = '#2ecc71'
        elif 300 <= obj.status_code < 400: color = '#3498db'
        elif 400 <= obj.status_code < 500: color = '#f39c12'
        else: color = '#e74c3c'
        return format_html('<span style="color: {}; font-weight: bold;">{}</span>', color, obj.status_code or 'N/A')
    status_code_display.short_description = 'Status'

    def response_time_display(self, obj):
        if not obj.response_time: return 'N/A'
        color = '#2ecc71' if obj.response_time < 0.5 else '#f39c12' if obj.response_time < 2 else '#e74c3c'
        return format_html('<span style="color: {}; font-weight: bold;">{:.3f}s</span>', color, obj.response_time)
    response_time_display.short_description = 'Time'

    def is_suspicious_display(self, obj):
        if obj.is_suspicious:
            return format_html('<span style="color: red; font-weight: bold;">⚠️ Suspicious</span>')
        return format_html('<span style="color: green;">✓ Normal</span>')
    is_suspicious_display.short_description = 'Security'

    def path_short(self, obj):
        return (obj.path[:50] + '...') if len(obj.path) > 50 else obj.path
    path_short.short_description = 'Path'

    def user_display(self, obj):
        if obj.user:
            return format_html('<a href="/admin/auth/user/{}/change/">{}</a>', obj.user.id, obj.user.username)
        return 'Anonymous'
    user_display.short_description = 'User'

    def timestamp_short(self, obj):
        return obj.timestamp.strftime('%Y-%m-%d %H:%M:%S')
    timestamp_short.short_description = 'Timestamp'

    def raw_geolocation_data_preview(self, obj):
        if not hasattr(obj, 'raw_geolocation_data') or not obj.raw_geolocation_data:
            return "No raw data"
        formatted = json.dumps(obj.raw_geolocation_data, indent=2, ensure_ascii=False)
        return format_html('<pre style="max-height: 300px; overflow: auto;">{}</pre>', formatted)

    # --- Actions ---
    actions = ['export_as_csv', 'delete_old_logs']

    @admin.action(description="Export selected logs as CSV")
    def export_as_csv(self, request, queryset):
        f = StringIO()
        writer = csv.writer(f)
        writer.writerow(['IP Address', 'Path', 'Method', 'User', 'Timestamp', 'Status Code', 'Response Time', 'Country'])
        for log in queryset:
            writer.writerow([
                log.ip_address, log.path, log.method, 
                log.user.username if log.user else 'Anonymous',
                log.timestamp.isoformat(), log.status_code, log.response_time, log.country or 'Unknown'
            ])
        f.seek(0)
        response = HttpResponse(f, content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename=request_logs.csv'
        return response

    @admin.action(description="Delete logs older than 30 days")
    def delete_old_logs(self, request, queryset):
        thirty_days_ago = timezone.now() - timedelta(days=30)
        old_logs = RequestLog.objects.filter(timestamp__lt=thirty_days_ago)
        count = old_logs.count()
        old_logs.delete()
        self.message_user(request, f"Deleted {count} logs older than 30 days")

    def has_add_permission(self, request): return False
    def has_change_permission(self, request, obj=None): return False

@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address',
        'severity_badge',
        'status_badge',
        'reason',
        'request_count',
        'last_detected',
    ]
    
    def severity_badge(self, obj):
        colors = {'high': 'red', 'medium': 'orange', 'low': 'blue'}
        return format_html('<b style="color: {}">{}</b>', colors.get(obj.severity, 'black'), obj.get_severity_display())
    severity_badge.short_description = 'Severity'

    def status_badge(self, obj):
        colors = {'blocked': 'red', 'watched': 'orange', 'cleared': 'green'}
        return format_html('<b style="color: {}">{}</b>', colors.get(obj.status, 'black'), obj.get_status_display())
    status_badge.short_description = 'Status'

@admin.register(AnomalyDetectionLog)
class AnomalyDetectionLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'event_type', 'severity', 'description']
    list_filter = ['event_type', 'severity']
