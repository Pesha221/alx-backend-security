# ip_tracking/models.py
from django.db import models
from django.utils import timezone
# ip_tracking/models.py
from django.db import models
from django.conf import settings
from django.core.cache import cache
import json


class RequestLog(models.Model):
    """
    Model to store basic request information for IP tracking.
    """

    # IP Information
    ip_address = models.GenericIPAddressField()

    # Request Information
    path = models.CharField(max_length=500)
    method = models.CharField(max_length=10)
    query_string = models.TextField(blank=True)

    # User Information (optional)
    user = models.ForeignKey(
        "auth.User",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="request_logs",
    )

    # User Agent Information
    user_agent = models.TextField(blank=True)
    is_mobile = models.BooleanField(default=False)
    is_tablet = models.BooleanField(default=False)
    is_touch_capable = models.BooleanField(default=False)
    is_pc = models.BooleanField(default=False)
    is_bot = models.BooleanField(default=False)
    browser = models.CharField(max_length=200, blank=True)
    browser_version = models.CharField(max_length=50, blank=True)
    os = models.CharField(max_length=100, blank=True)
    os_version = models.CharField(max_length=50, blank=True)
    device = models.CharField(max_length=200, blank=True)

    # Response Information
    status_code = models.IntegerField(null=True, blank=True)
    response_size = models.IntegerField(null=True, blank=True)

    # Timing
    timestamp = models.DateTimeField(auto_now_add=True)
    response_time = models.FloatField(
        help_text="Response time in seconds", null=True, blank=True
    )

    # Geolocation (optional, can be populated later)
    country = models.CharField(max_length=100, blank=True)
    city = models.CharField(max_length=100, blank=True)
    region = models.CharField(max_length=100, blank=True)

    # Meta Information
    referer = models.URLField(blank=True)
    content_type = models.CharField(max_length=100, blank=True)

    class Meta:
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
        ordering = ["-timestamp"]
        indexes = [
            models.Index(fields=["ip_address"]),
            models.Index(fields=["timestamp"]),
            models.Index(fields=["path"]),
            models.Index(fields=["user"]),
            models.Index(fields=["status_code"]),
        ]

    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp.strftime('%Y-%m-%d %H:%M')}"

    @property
    def is_successful(self):
        """Check if the request was successful (2xx or 3xx status codes)"""
        return self.status_code and 200 <= self.status_code < 400

    @property
    def is_error(self):
        """Check if the request resulted in an error (4xx or 5xx status codes)"""
        return self.status_code and self.status_code >= 400

    @classmethod
    def get_recent_requests(cls, hours=24):
        """Get recent requests within specified hours"""
        from django.utils import timezone
        from datetime import timedelta

        time_threshold = timezone.now() - timedelta(hours=hours)
        return cls.objects.filter(timestamp__gte=time_threshold)

    @classmethod
    def get_requests_by_ip(cls, ip_address, hours=24):
        """Get recent requests from a specific IP address"""
        from django.utils import timezone
        from datetime import timedelta

        time_threshold = timezone.now() - timedelta(hours=hours)
        return cls.objects.filter(
            ip_address=ip_address, timestamp__gte=time_threshold
        ).order_by("-timestamp")


class RequestLog(models.Model):
    """
    Enhanced request log model with geolocation data.
    """
    # Existing fields
    ip_address = models.GenericIPAddressField(db_index=True)
    user_agent = models.TextField(blank=True, null=True)
    path = models.CharField(max_length=500, db_index=True)
    method = models.CharField(max_length=10)
    status_code = models.IntegerField()
    response_time = models.FloatField(help_text="Response time in seconds")
    timestamp = models.DateTimeField(auto_now_add=True)
    
    # New geolocation fields
    country = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    country_code = models.CharField(max_length=10, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True, db_index=True)
    region = models.CharField(max_length=100, blank=True, null=True)
    latitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    longitude = models.DecimalField(max_digits=9, decimal_places=6, blank=True, null=True)
    timezone = models.CharField(max_length=50, blank=True, null=True)
    
    # ISP/Network information
    isp = models.CharField(max_length=200, blank=True, null=True)
    organization = models.CharField(max_length=200, blank=True, null=True)
    asn = models.CharField(max_length=50, blank=True, null=True, help_text="Autonomous System Number")
    
    # Additional metadata
    is_vpn = models.BooleanField(default=False)
    is_proxy = models.BooleanField(default=False)
    is_tor = models.BooleanField(default=False)
    is_hosting = models.BooleanField(default=False)
    
    # Raw geolocation data (for debugging/advanced analysis)
    raw_geolocation_data = models.JSONField(blank=True, null=True)
    
    # User information (if available)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='request_logs'
    )
    
    # Request metadata
    referer = models.URLField(max_length=1000, blank=True, null=True)
    query_string = models.CharField(max_length=1000, blank=True, null=True)
    content_type = models.CharField(max_length=100, blank=True, null=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['country']),
            models.Index(fields=['city']),
            models.Index(fields=['timestamp', 'country']),
            models.Index(fields=['timestamp', 'city']),
        ]
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} - {self.timestamp}"
    
    @property
    def location_summary(self):
        """Get location summary string"""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.region:
            parts.append(self.region)
        if self.country:
            parts.append(self.country)
        return ", ".join(parts) if parts else "Unknown location"
    
    @property
    def is_suspicious(self):
        """Check if the request is suspicious based on geolocation"""
        return any([
            self.is_vpn,
            self.is_proxy,
            self.is_tor,
            self.is_hosting,
        ])
    
    def save_geolocation_data(self, geolocation_data):
        """Save geolocation data to model"""
        if not geolocation_data:
            return
        
        # Store raw data
        self.raw_geolocation_data = geolocation_data
        
        # Extract and store structured data
        self.country = geolocation_data.get('country')
        self.country_code = geolocation_data.get('country_code')
        self.city = geolocation_data.get('city')
        self.region = geolocation_data.get('region')
        
        # Coordinates
        lat = geolocation_data.get('latitude')
        lon = geolocation_data.get('longitude')
        if lat and lon:
            self.latitude = lat
            self.longitude = lon
        
        # Timezone
        self.timezone = geolocation_data.get('timezone')
        
        # Network information
        self.isp = geolocation_data.get('isp')
        self.organization = geolocation_data.get('org')
        self.asn = geolocation_data.get('asn')
        
        # Security flags
        self.is_vpn = geolocation_data.get('is_vpn', False)
        self.is_proxy = geolocation_data.get('is_proxy', False)
        self.is_tor = geolocation_data.get('is_tor', False)
        self.is_hosting = geolocation_data.get('is_hosting', False)
        
        self.save(update_fields=[
            'country', 'country_code', 'city', 'region',
            'latitude', 'longitude', 'timezone',
            'isp', 'organization', 'asn',
            'is_vpn', 'is_proxy', 'is_tor', 'is_hosting',
            'raw_geolocation_data'
        ])


# ip_tracking/models.py (add this model)
from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

class RateLimit(models.Model):
    """
    Model to track rate limiting violations and blocks.
    """
    ip_address = models.GenericIPAddressField(db_index=True)
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='rate_limits'
    )
    
    # Rate limiting data
    key = models.CharField(max_length=200, db_index=True)
    count = models.IntegerField(default=0)
    period = models.IntegerField(help_text="Period in seconds")
    limit = models.IntegerField(help_text="Maximum allowed requests")
    
    # Blocking information
    is_blocked = models.BooleanField(default=False)
    blocked_at = models.DateTimeField(null=True, blank=True)
    blocked_until = models.DateTimeField(null=True, blank=True)
    block_reason = models.TextField(blank=True, null=True)
    
    # Violation tracking
    violation_count = models.IntegerField(default=0)
    last_violation = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['ip_address', 'is_blocked']),
            models.Index(fields=['key', 'created_at']),
        ]
        unique_together = ['ip_address', 'key']
    
    def __str__(self):
        return f"{self.ip_address} - {self.key} ({self.count}/{self.limit})"
    
    @property
    def is_currently_blocked(self):
        """Check if IP is currently blocked"""
        if not self.is_blocked:
            return False
        
        if self.blocked_until and timezone.now() < self.blocked_until:
            return True
        
        # Auto-unblock if block has expired
        if self.blocked_until and timezone.now() >= self.blocked_until:
            self.is_blocked = False
            self.save()
            return False
        
        return self.is_blocked
    
    @property
    def remaining_requests(self):
        """Calculate remaining requests"""
        return max(0, self.limit - self.count)
    
    @property
    def reset_time(self):
        """Calculate when the rate limit resets"""
        if self.created_at:
            reset_time = self.created_at + timedelta(seconds=self.period)
            return reset_time
        return None
    
    @property
    def seconds_until_reset(self):
        """Calculate seconds until rate limit resets"""
        reset_time = self.reset_time
        if reset_time:
            delta = reset_time - timezone.now()
            return max(0, int(delta.total_seconds()))
        return 0
    
    def increment(self):
        """Increment request count"""
        self.count += 1
        self.save()
    
    def reset(self):
        """Reset request count"""
        self.count = 0
        self.save()
    
    def block(self, duration_seconds=3600, reason=""):
        """Block this IP address"""
        self.is_blocked = True
        self.blocked_at = timezone.now()
        self.blocked_until = timezone.now() + timedelta(seconds=duration_seconds)
        self.block_reason = reason
        self.save()
    
    def unblock(self):
        """Unblock this IP address"""
        self.is_blocked = False
        self.blocked_at = None
        self.blocked_until = None
        self.block_reason = ""
        self.save()
    
    def record_violation(self):
        """Record a rate limit violation"""
        self.violation_count += 1
        self.last_violation = timezone.now()
        self.save()
    
    @classmethod
    def get_or_create_for_ip(cls, ip_address, key, limit, period):
        """Get or create rate limit record for IP"""
        # Check for existing record within period
        cutoff_time = timezone.now() - timedelta(seconds=period)
        
        try:
            rate_limit = cls.objects.get(
                ip_address=ip_address,
                key=key,
                created_at__gte=cutoff_time
            )
        except cls.DoesNotExist:
            # Create new record
            rate_limit = cls.objects.create(
                ip_address=ip_address,
                key=key,
                limit=limit,
                period=period,
                count=0
            )
        
        return rate_limit
    
    @classmethod
    def cleanup_old_records(cls, days=7):
        """Clean up old rate limit records"""
        cutoff_date = timezone.now() - timedelta(days=days)
        deleted, _ = cls.objects.filter(created_at__lt=cutoff_date).delete()
        return deleted

# ip_tracking/models.py (add these models)
from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import json

class SuspiciousIP(models.Model):
    """
    Model to track suspicious IP addresses with anomaly detection.
    """
    REASON_CHOICES = [
        ('high_request_rate', 'High Request Rate'),
        ('sensitive_path_access', 'Sensitive Path Access'),
        ('multiple_failed_logins', 'Multiple Failed Logins'),
        ('scanner_detected', 'Security Scanner Detected'),
        ('suspicious_country', 'Suspicious Country'),
        ('vpn_proxy_detected', 'VPN/Proxy Detected'),
        ('tor_network', 'TOR Network'),
        ('brute_force_attempt', 'Brute Force Attempt'),
        ('sql_injection_pattern', 'SQL Injection Pattern'),
        ('xss_attempt', 'XSS Attempt'),
        ('dos_attempt', 'Denial of Service Attempt'),
        ('credential_stuffing', 'Credential Stuffing'),
        ('api_abuse', 'API Abuse'),
        ('data_scraping', 'Data Scraping'),
        ('malicious_bot', 'Malicious Bot'),
        ('unknown', 'Unknown'),
    ]
    
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('active', 'Active'),
        ('investigating', 'Under Investigation'),
        ('false_positive', 'False Positive'),
        ('resolved', 'Resolved'),
        ('whitelisted', 'Whitelisted'),
        ('blacklisted', 'Blacklisted'),
    ]
    
    # Basic information
    ip_address = models.GenericIPAddressField(unique=True, db_index=True)
    reason = models.CharField(max_length=50, choices=REASON_CHOICES)
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='active')
    
    # Detection details
    confidence_score = models.FloatField(default=0.0, help_text="0.0 to 1.0")
    detection_method = models.CharField(max_length=100, blank=True, null=True)
    first_detected = models.DateTimeField(auto_now_add=True)
    last_detected = models.DateTimeField(auto_now=True)
    
    # Associated data
    request_count = models.IntegerField(default=0, help_text="Number of requests from this IP")
    user_agents = models.JSONField(default=list, blank=True, help_text="List of user agents used")
    accessed_paths = models.JSONField(default=list, blank=True, help_text="Paths accessed by this IP")
    countries = models.JSONField(default=list, blank=True, help_text="Countries associated with this IP")
    
    # Geolocation data
    country = models.CharField(max_length=100, blank=True, null=True)
    city = models.CharField(max_length=100, blank=True, null=True)
    isp = models.CharField(max_length=200, blank=True, null=True)
    is_vpn = models.BooleanField(default=False)
    is_proxy = models.BooleanField(default=False)
    is_tor = models.BooleanField(default=False)
    
    # Threat intelligence
    threat_intelligence = models.JSONField(default=dict, blank=True, help_text="External threat intelligence data")
    known_malicious = models.BooleanField(default=False)
    known_botnet = models.BooleanField(default=False)
    spamhaus_listed = models.BooleanField(default=False)
    
    # Investigation data
    investigator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='investigated_ips'
    )
    investigation_notes = models.TextField(blank=True, null=True)
    resolution_notes = models.TextField(blank=True, null=True)
    
    # Auto-block configuration
    auto_block = models.BooleanField(default=False)
    block_duration = models.IntegerField(default=86400, help_text="Block duration in seconds")
    blocked_until = models.DateTimeField(null=True, blank=True)
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-first_detected']
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
        indexes = [
            models.Index(fields=['ip_address', 'status']),
            models.Index(fields=['severity', 'status']),
            models.Index(fields=['first_detected', 'severity']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.get_reason_display()} ({self.severity})"
    
    @property
    def is_currently_blocked(self):
        """Check if IP is currently blocked"""
        if not self.auto_block:
            return False
        
        if self.blocked_until and timezone.now() < self.blocked_until:
            return True
        
        # Auto-unblock if block has expired
        if self.blocked_until and timezone.now() >= self.blocked_until:
            self.auto_block = False
            self.save()
            return False
        
        return self.auto_block
    
    @property
    def block_time_remaining(self):
        """Get remaining block time in seconds"""
        if self.blocked_until and self.is_currently_blocked:
            delta = self.blocked_until - timezone.now()
            return max(0, int(delta.total_seconds()))
        return 0
    
    @property
    def threat_level(self):
        """Calculate threat level based on multiple factors"""
        score = 0
        
        # Base score from severity
        severity_scores = {
            'low': 1,
            'medium': 2,
            'high': 3,
            'critical': 4,
        }
        score += severity_scores.get(self.severity, 1)
        
        # Add confidence score
        score += self.confidence_score
        
        # Add bonus for known malicious
        if self.known_malicious:
            score += 2
        
        # Add bonus for VPN/Proxy/TOR
        if self.is_vpn or self.is_proxy:
            score += 1
        if self.is_tor:
            score += 2
        
        # Add bonus for suspicious country
        from django.conf import settings
        suspicious_countries = settings.ANOMALY_DETECTION.get('SUSPICIOUS_COUNTRIES', [])
        if self.country in suspicious_countries:
            score += 1
        
        # Normalize to 0-10 scale
        return min(10, max(1, round(score)))
    
    def update_statistics(self, request_log):
        """Update statistics with new request data"""
        from .models import RequestLog
        
        # Increment request count
        self.request_count += 1
        
        # Update user agents
        if request_log.user_agent and request_log.user_agent not in self.user_agents:
            self.user_agents.append(request_log.user_agent)
            self.user_agents = self.user_agents[:10]  # Keep only last 10
        
        # Update accessed paths
        if request_log.path and request_log.path not in self.accessed_paths:
            self.accessed_paths.append(request_log.path)
            self.accessed_paths = self.accessed_paths[:20]  # Keep only last 20
        
        # Update countries
        if request_log.country and request_log.country not in self.countries:
            self.countries.append(request_log.country)
        
        # Update geolocation if not set
        if not self.country and request_log.country:
            self.country = request_log.country
            self.city = request_log.city
            self.isp = request_log.isp
            self.is_vpn = request_log.is_vpn
            self.is_proxy = request_log.is_proxy
            self.is_tor = request_log.is_tor
        
        self.save()
    
    def block_ip(self, duration_seconds=86400, notes=""):
        """Block this IP address"""
        self.auto_block = True
        self.block_duration = duration_seconds
        self.blocked_until = timezone.now() + timedelta(seconds=duration_seconds)
        self.investigation_notes = notes
        self.save()
    
    def unblock_ip(self, notes=""):
        """Unblock this IP address"""
        self.auto_block = False
        self.blocked_until = None
        self.resolution_notes = notes
        self.save()
    
    def mark_false_positive(self, investigator=None, notes=""):
        """Mark as false positive"""
        self.status = 'false_positive'
        self.severity = 'low'
        self.investigator = investigator
        self.resolution_notes = notes
        self.save()
    
    def mark_resolved(self, investigator=None, notes=""):
        """Mark as resolved"""
        self.status = 'resolved'
        self.investigator = investigator
        self.resolution_notes = notes
        self.save()
    
    def whitelist(self, investigator=None, notes=""):
        """Add to whitelist"""
        self.status = 'whitelisted'
        self.investigator = investigator
        self.resolution_notes = notes
        self.save()
    
    def blacklist(self, investigator=None, notes=""):
        """Add to blacklist"""
        self.status = 'blacklisted'
        self.severity = 'critical'
        self.investigator = investigator
        self.resolution_notes = notes
        self.save()
    
    @classmethod
    def get_or_create_suspicious_ip(cls, ip_address, reason, severity='medium', confidence=0.5):
        """Get or create suspicious IP record"""
        try:
            suspicious_ip = cls.objects.get(ip_address=ip_address)
            # Update if exists
            if suspicious_ip.status not in ['resolved', 'false_positive', 'whitelisted']:
                suspicious_ip.reason = reason
                suspicious_ip.severity = severity
                suspicious_ip.confidence_score = max(suspicious_ip.confidence_score, confidence)
                suspicious_ip.save()
        except cls.DoesNotExist:
            suspicious_ip = cls.objects.create(
                ip_address=ip_address,
                reason=reason,
                severity=severity,
                confidence_score=confidence,
                status='active'
            )
        
        return suspicious_ip


class AnomalyDetectionLog(models.Model):
    """
    Log for anomaly detection activities.
    """
    ip_address = models.GenericIPAddressField(db_index=True)
    detection_type = models.CharField(max_length=50)
    severity = models.CharField(max_length=20)
    confidence_score = models.FloatField()
    details = models.JSONField(default=dict)
    triggered_rules = models.JSONField(default=list)
    timestamp = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address', 'timestamp']),
            models.Index(fields=['detection_type', 'timestamp']),
        ]
    
    def __str__(self):
        return f"{self.ip_address} - {self.detection_type} - {self.timestamp}"
    
    # ip_tracking/models.py
from django.db import models
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
import json

class BlockedIP(models.Model):
    """
    Model to store blocked IP addresses.
    """
    BLOCK_TYPES = [
        ('permanent', 'Permanent Block'),
        ('temporary', 'Temporary Block'),
        ('rate_limit', 'Rate Limit Block'),
        ('manual', 'Manual Block'),
        ('suspicious', 'Suspicious Activity'),
        ('abuse', 'Abuse/Misuse'),
        ('spam', 'Spam'),
        ('scanner', 'Security Scanner'),
        ('bot', 'Malicious Bot'),
        ('vpn_proxy', 'VPN/Proxy'),
        ('tor', 'TOR Network'),
        ('country', 'Country Block'),
        ('asn', 'ASN Block'),
    ]
    
    # Basic information
    ip_address = models.GenericIPAddressField(unique=True, db_index=True, verbose_name="IP Address")
    subnet_mask = models.PositiveIntegerField(
        default=32,
        blank=True,
        null=True,
        help_text="Subnet mask (8-32 for IPv4, 128 for IPv6)"
    )
    block_type = models.CharField(
        max_length=20, 
        choices=BLOCK_TYPES,
        default='manual',
        verbose_name="Block Type"
    )
    
    # Block duration
    is_permanent = models.BooleanField(default=False, verbose_name="Permanent Block")
    block_duration = models.IntegerField(
        default=86400,
        help_text="Block duration in seconds (only for temporary blocks)",
        verbose_name="Block Duration"
    )
    blocked_at = models.DateTimeField(auto_now_add=True, verbose_name="Blocked At")
    blocked_until = models.DateTimeField(
        null=True,
        blank=True,
        verbose_name="Blocked Until"
    )
    
    # Block details
    reason = models.TextField(help_text="Reason for blocking this IP", verbose_name="Block Reason")
    source = models.CharField(
        max_length=100,
        default='manual',
        help_text="Source of block (manual, automated, threat_intel, etc.)",
        verbose_name="Block Source"
    )
    evidence = models.JSONField(
        default=dict,
        blank=True,
        help_text="Evidence or data supporting the block",
        verbose_name="Block Evidence"
    )
    
    # Associated data
    request_count = models.IntegerField(
        default=0,
        help_text="Number of requests from this IP before blocking",
        verbose_name="Request Count"
    )
    user_agents = models.JSONField(
        default=list,
        blank=True,
        help_text="User agents used by this IP",
        verbose_name="User Agents"
    )
    accessed_paths = models.JSONField(
        default=list,
        blank=True,
        help_text="Paths accessed by this IP",
        verbose_name="Accessed Paths"
    )
    
    # Geolocation data (cached)
    country = models.CharField(max_length=100, blank=True, null=True, verbose_name="Country")
    country_code = models.CharField(max_length=10, blank=True, null=True, verbose_name="Country Code")
    city = models.CharField(max_length=100, blank=True, null=True, verbose_name="City")
    isp = models.CharField(max_length=200, blank=True, null=True, verbose_name="ISP")
    
    # Threat intelligence
    threat_score = models.IntegerField(
        default=0,
        help_text="Threat score (0-100)",
        verbose_name="Threat Score"
    )
    known_malicious = models.BooleanField(default=False, verbose_name="Known Malicious")
    spamhaus_listed = models.BooleanField(default=False, verbose_name="Spamhaus Listed")
    tor_exit_node = models.BooleanField(default=False, verbose_name="TOR Exit Node")
    
    # Metadata
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='blocked_ips',
        verbose_name="Created By"
    )
    notes = models.TextField(blank=True, null=True, verbose_name="Notes")
    
    # Auto-update fields
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
        ordering = ['-blocked_at']
        indexes = [
            models.Index(fields=['ip_address', 'is_permanent']),
            models.Index(fields=['block_type', 'blocked_at']),
            models.Index(fields=['country', 'blocked_at']),
        ]
    
    def __str__(self):
        duration = "Permanent" if self.is_permanent else f"{self.block_duration}s"
        return f"{self.ip_address} - {self.get_block_type_display()} ({duration})"
    
    def save(self, *args, **kwargs):
        """Override save to handle block duration"""
        if not self.is_permanent and self.block_duration > 0:
            if not self.blocked_until:
                self.blocked_until = timezone.now() + timedelta(seconds=self.block_duration)
        else:
            self.blocked_until = None
        
        super().save(*args, **kwargs)
    
    @property
    def is_active(self):
        """Check if the block is currently active"""
        if self.is_permanent:
            return True
        
        if self.blocked_until:
            return timezone.now() < self.blocked_until
        
        return False
    
    @property
    def time_remaining(self):
        """Get remaining block time in seconds"""
        if self.is_permanent or not self.blocked_until:
            return None
        
        delta = self.blocked_until - timezone.now()
        return max(0, int(delta.total_seconds()))
    
    @property
    def cidr_notation(self):
        """Get IP in CIDR notation"""
        if self.subnet_mask:
            return f"{self.ip_address}/{self.subnet_mask}"
        return self.ip_address
    
    @property
    def display_duration(self):
        """Get human-readable block duration"""
        if self.is_permanent:
            return "Permanent"
        
        if not self.block_duration:
            return "Unknown"
        
        # Convert seconds to human readable
        seconds = self.block_duration
        days, seconds = divmod(seconds, 86400)
        hours, seconds = divmod(seconds, 3600)
        minutes, seconds = divmod(seconds, 60)
        
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        if minutes > 0:
            parts.append(f"{minutes}m")
        if seconds > 0 or not parts:
            parts.append(f"{seconds}s")
        
        return " ".join(parts)
    
    def unblock(self):
        """Unblock this IP address"""
        self.delete()
    
    def extend_block(self, additional_seconds):
        """Extend block duration"""
        if not self.is_permanent:
            self.block_duration += additional_seconds
            if self.blocked_until:
                self.blocked_until += timedelta(seconds=additional_seconds)
            self.save()
    
    @classmethod
    def block_ip(cls, ip_address, reason, block_type='manual', duration=86400, 
                 is_permanent=False, created_by=None, evidence=None, **kwargs):
        """
        Block an IP address with all necessary data.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            block_type: Type of block (from BLOCK_TYPES)
            duration: Block duration in seconds (for temporary blocks)
            is_permanent: Whether block is permanent
            created_by: User who created the block
            evidence: Supporting evidence for the block
            **kwargs: Additional data to save
            
        Returns:
            BlockedIP instance
        """
        # Check if already blocked
        existing_block = cls.objects.filter(ip_address=ip_address).first()
        if existing_block:
            return existing_block
        
        # Create new block
        blocked_ip = cls(
            ip_address=ip_address,
            reason=reason,
            block_type=block_type,
            block_duration=duration,
            is_permanent=is_permanent,
            created_by=created_by,
            evidence=evidence or {},
        )
        
        # Set additional fields from kwargs
        for key, value in kwargs.items():
            if hasattr(blocked_ip, key):
                setattr(blocked_ip, key, value)
        
        blocked_ip.save()
        return blocked_ip
    
    @classmethod
    def is_ip_blocked(cls, ip_address):
        """
        Check if an IP address is currently blocked.
        
        Args:
            ip_address: IP address to check
            
        Returns:
            BlockedIP instance if blocked, None otherwise
        """
        try:
            # First check exact match
            blocked_ip = cls.objects.filter(
                ip_address=ip_address,
                is_permanent=True
            ).first()
            
            if blocked_ip:
                return blocked_ip
            
            # Check temporary blocks that are still active
            blocked_ip = cls.objects.filter(
                ip_address=ip_address,
                is_permanent=False,
                blocked_until__gt=timezone.now()
            ).first()
            
            if blocked_ip:
                return blocked_ip
            
            # Check for subnet blocks (CIDR notation)
            # This is a simplified check - in production you'd want proper CIDR matching
            blocked_subnets = cls.objects.filter(
                subnet_mask__isnull=False
            ).exclude(subnet_mask=32)
            
            for block in blocked_subnets:
                if cls._ip_in_subnet(ip_address, block.ip_address, block.subnet_mask):
                    return block
            
            return None
            
        except Exception as e:
            # Log error but don't block if we can't check
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Error checking if IP is blocked: {e}")
            return None
    
    @staticmethod
    def _ip_in_subnet(ip, subnet_ip, mask):
        """
        Check if IP is in subnet (CIDR notation).
        This is a simplified version - use ipaddress module for production.
        """
        try:
            from ipaddress import ip_network, ip_address as ip_addr
            
            network = ip_network(f"{subnet_ip}/{mask}", strict=False)
            return ip_addr(ip) in network
            
        except:
            return False
    
    @classmethod
    def get_active_blocks(cls):
        """Get all currently active blocks"""
        return cls.objects.filter(
            models.Q(is_permanent=True) |
            models.Q(blocked_until__gt=timezone.now())
        )
    
    @classmethod
    def cleanup_expired_blocks(cls):
        """Remove expired temporary blocks"""
        expired = cls.objects.filter(
            is_permanent=False,
            blocked_until__lt=timezone.now()
        )
        count = expired.count()
        expired.delete()
        return count
