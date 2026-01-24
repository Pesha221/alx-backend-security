# ip_tracking/admin.py
import json
from django.contrib import admin
from django.utils.html import format_html
from .models import RequestLog, SuspiciousIP, AnomalyDetectionLog

@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = [
        'ip_address',
        'path',
        'method',
        'status_code',
        'response_time',
        'timestamp',
        'security_flags',
    ]
    
    list_filter = ['method', 'status_code', 'country', 'timestamp'] #
    readonly_fields = ['timestamp', 'raw_geolocation_data_preview']

    def security_flags(self, obj):
        flags = []
        if obj.is_vpn: flags.append("VPN")
        if obj.is_proxy: flags.append("Proxy")
        if obj.is_tor: flags.append("TOR")
        if obj.is_hosting: flags.append("Hosting/Bot")
        return ", ".join(flags) if flags else "Clean"
    security_flags.short_description = 'Network Status'

    def raw_geolocation_data_preview(self, obj):
        if not hasattr(obj, 'raw_geolocation_data') or not obj.raw_geolocation_data:
            return "No data"
        return format_html('<pre>{}</pre>', json.dumps(obj.raw_geolocation_data, indent=2))

admin.site.register(SuspiciousIP)
admin.site.register(AnomalyDetectionLog)
