# ip_tracking/admin.py
import json
from django.contrib import admin
from django.utils.html import format_html
from .models import RequestLog, SuspiciousIP, AnomalyDetectionLog

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address',
        'path_short',
        'method',
        'status_code',
        'response_time',
        'timestamp',
        'is_suspicious_display',
    ]
    
    # list_filter MUST only contain actual database fields
    list_filter = [
        'method',
        'status_code',
        'country',
        'timestamp',
    ]
    
    search_fields = ['ip_address', 'path', 'user_agent']
    readonly_fields = ['timestamp', 'raw_geolocation_data_preview']

    def path_short(self, obj):
        return obj.path[:50] + "..." if len(obj.path) > 50 else obj.path

    def is_suspicious_display(self, obj):
        if getattr(obj, 'is_suspicious', False):
            return format_html('<span style="color: red;">⚠️ Suspicious</span>')
        return "Normal"
    is_suspicious_display.short_description = 'Status'

    def raw_geolocation_data_preview(self, obj):
        if not hasattr(obj, 'raw_geolocation_data') or not obj.raw_geolocation_data:
            return "No raw data"
        return format_html('<pre>{}</pre>', json.dumps(obj.raw_geolocation_data, indent=2))

@admin.register(SuspiciousIP)
class SuspiciousIPAdmin(admin.ModelAdmin):
    list_display = ['ip_address', 'severity', 'status', 'last_detected']
    list_filter = ['severity', 'status']
    search_fields = ['ip_address', 'reason']

@admin.register(AnomalyDetectionLog)
class AnomalyDetectionLogAdmin(admin.ModelAdmin):
    # Fixed to include only valid fields
    list_display = ['timestamp', 'severity']
    list_filter = ['severity']
