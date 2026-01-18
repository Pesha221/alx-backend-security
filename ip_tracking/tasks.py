# ip_tracking/tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
from django.conf import settings
from django.db.models import Count, Q, F
from django.db import transaction
import logging
from .models import RequestLog, SuspiciousIP, AnomalyDetectionLog
from .geolocation import IPGeolocationService

logger = logging.getLogger(__name__)

@shared_task(bind=True, max_retries=3)
def detect_anomalies_task(self, hours_back=1):
    """
    Celery task to detect anomalous IP activity.
    Runs hourly to flag suspicious IPs.
    
    Args:
        hours_back: Number of hours to look back
    """
    try:
        logger.info(f"Starting anomaly detection for last {hours_back} hours")
        
        # Get configuration
        config = getattr(settings, 'ANOMALY_DETECTION', {})
        if not config.get('ENABLED', True):
            logger.info("Anomaly detection is disabled")
            return
        
        threshold = config.get('REQUEST_THRESHOLD', 100)
        sensitive_paths = config.get('SENSITIVE_PATHS', [])
        high_risk_paths = config.get('HIGH_RISK_PATHS', [])
        min_requests = config.get('MIN_REQUESTS_FOR_ANALYSIS', 5)
        
        # Calculate time range
        end_time = timezone.now()
        start_time = end_time - timedelta(hours=hours_back)
        
        # Get all IPs with requests in the time period
        ip_stats = RequestLog.objects.filter(
            timestamp__range=[start_time, end_time]
        ).values('ip_address').annotate(
            request_count=Count('id'),
            unique_paths=Count('path', distinct=True),
            failed_logins=Count('id', filter=Q(path__icontains='/login', status_code=401)),
            sensitive_access=Count('id', filter=Q(path__in=sensitive_paths)),
            high_risk_access=Count('id', filter=Q(path__in=high_risk_paths)),
        ).filter(
            request_count__gte=min_requests
        ).order_by('-request_count')
        
        logger.info(f"Analyzing {len(ip_stats)} IP addresses")
        
        detected_anomalies = []
        
        for ip_stat in ip_stats:
            ip_address = ip_stat['ip_address']
            request_count = ip_stat['request_count']
            unique_paths = ip_stat['unique_paths']
            failed_logins = ip_stat['failed_logins']
            sensitive_access = ip_stat['sensitive_access']
            high_risk_access = ip_stat['high_risk_access']
            
            # Initialize anomaly detection
            anomalies = []
            confidence = 0.0
            severity = 'low'
            
            # Rule 1: High request rate
            if request_count > threshold:
                anomalies.append({
                    'type': 'high_request_rate',
                    'value': request_count,
                    'threshold': threshold,
                    'confidence': min(1.0, request_count / threshold * 0.8)
                })
                confidence += 0.4
                severity = 'high' if request_count > threshold * 2 else 'medium'
            
            # Rule 2: Access to sensitive paths
            if sensitive_access > 0:
                anomalies.append({
                    'type': 'sensitive_path_access',
                    'value': sensitive_access,
                    'paths': sensitive_paths,
                    'confidence': min(1.0, sensitive_access * 0.3)
                })
                confidence += 0.3
                severity = 'high' if high_risk_access > 0 else 'medium'
            
            # Rule 3: Multiple failed logins
            if failed_logins >= 5:
                anomalies.append({
                    'type': 'multiple_failed_logins',
                    'value': failed_logins,
                    'confidence': min(1.0, failed_logins * 0.2)
                })
                confidence += 0.3
                severity = 'high'
            
            # Rule 4: Suspicious user agents
            suspicious_agents = detect_suspicious_user_agents(ip_address, start_time, end_time)
            if suspicious_agents:
                anomalies.append({
                    'type': 'scanner_detected',
                    'agents': suspicious_agents,
                    'confidence': 0.8
                })
                confidence += 0.5
                severity = 'critical'
            
            # Rule 5: Suspicious geolocation
            geolocation_risk = check_geolocation_risk(ip_address)
            if geolocation_risk:
                anomalies.append({
                    'type': 'suspicious_country',
                    'details': geolocation_risk,
                    'confidence': geolocation_risk.get('confidence', 0.5)
                })
                confidence += geolocation_risk.get('confidence', 0.5)
                severity = max(severity, geolocation_risk.get('severity', 'medium'))
            
            # Rule 6: VPN/Proxy/TOR detection
            network_risk = check_network_risk(ip_address)
            if network_risk:
                anomalies.append({
                    'type': 'vpn_proxy_detected',
                    'details': network_risk,
                    'confidence': 0.6
                })
                confidence += 0.3
                severity = 'medium'
            
            # Check if anomalies meet confidence threshold
            if confidence >= config.get('CONFIDENCE_THRESHOLD', 0.7):
                # Create or update suspicious IP record
                with transaction.atomic():
                    suspicious_ip = SuspiciousIP.get_or_create_suspicious_ip(
                        ip_address=ip_address,
                        reason=determine_primary_reason(anomalies),
                        severity=severity,
                        confidence=confidence
                    )
                    
                    # Update statistics
                    recent_logs = RequestLog.objects.filter(
                        ip_address=ip_address,
                        timestamp__range=[start_time, end_time]
                    )[:10]
                    
                    for log in recent_logs:
                        suspicious_ip.update_statistics(log)
                    
                    # Log the detection
                    AnomalyDetectionLog.objects.create(
                        ip_address=ip_address,
                        detection_type='automated',
                        severity=severity,
                        confidence_score=confidence,
                        details={
                            'request_count': request_count,
                            'unique_paths': unique_paths,
                            'failed_logins': failed_logins,
                            'sensitive_access': sensitive_access,
                            'high_risk_access': high_risk_access,
                            'time_range': {
                                'start': start_time.isoformat(),
                                'end': end_time.isoformat(),
                            }
                        },
                        triggered_rules=[a['type'] for a in anomalies]
                    )
                    
                    detected_anomalies.append({
                        'ip_address': ip_address,
                        'severity': severity,
                        'confidence': confidence,
                        'anomalies': anomalies,
                        'request_count': request_count,
                    })
        
        logger.info(f"Anomaly detection completed. Found {len(detected_anomalies)} suspicious IPs")
        
        # Send notification for critical anomalies
        critical_anomalies = [a for a in detected_anomalies if a['severity'] in ['high', 'critical']]
        if critical_anomalies:
            send_anomaly_notification.delay(critical_anomalies)
        
        return {
            'status': 'success',
            'detected_anomalies': len(detected_anomalies),
            'critical_anomalies': len(critical_anomalies),
            'time_range': {
                'start': start_time.isoformat(),
                'end': end_time.isoformat(),
            }
        }
        
    except Exception as e:
        logger.error(f"Error in anomaly detection task: {e}")
        raise self.retry(exc=e, countdown=60)


@shared_task
def detect_suspicious_user_agents(ip_address, start_time, end_time):
    """
    Detect suspicious user agents for an IP address.
    """
    try:
        config = getattr(settings, 'ANOMALY_DETECTION', {})
        suspicious_patterns = config.get('USER_AGENT_PATTERNS', [])
        
        if not suspicious_patterns:
            return []
        
        # Get user agents for this IP
        user_agents = RequestLog.objects.filter(
            ip_address=ip_address,
            timestamp__range=[start_time, end_time],
            user_agent__isnull=False
        ).values_list('user_agent', flat=True).distinct()
        
        suspicious_agents = []
        
        for agent in user_agents:
            agent_lower = agent.lower()
            for pattern in suspicious_patterns:
                if pattern.lower() in agent_lower:
                    suspicious_agents.append({
                        'user_agent': agent,
                        'pattern': pattern,
                    })
                    break
        
        return suspicious_agents
        
    except Exception as e:
        logger.error(f"Error detecting suspicious user agents: {e}")
        return []


@shared_task
def check_geolocation_risk(ip_address):
    """
    Check geolocation risk for an IP address.
    """
    try:
        config = getattr(settings, 'ANOMALY_DETECTION', {})
        suspicious_countries = config.get('SUSPICIOUS_COUNTRIES', [])
        
        if not suspicious_countries:
            return None
        
        # Get geolocation data
        geolocation_data = IPGeolocationService.get_geolocation(ip_address)
        
        if not geolocation_data:
            return None
        
        country_code = geolocation_data.get('country_code')
        
        if country_code and country_code.upper() in suspicious_countries:
            return {
                'country': geolocation_data.get('country'),
                'country_code': country_code,
                'confidence': 0.7,
                'severity': 'medium',
                'details': geolocation_data,
            }
        
        return None
        
    except Exception as e:
        logger.error(f"Error checking geolocation risk: {e}")
        return None


@shared_task
def check_network_risk(ip_address):
    """
    Check network risk (VPN/Proxy/TOR) for an IP address.
    """
    try:
        # Get geolocation data
        geolocation_data = IPGeolocationService.get_geolocation(ip_address)
        
        if not geolocation_data:
            return None
        
        risk_factors = []
        
        if geolocation_data.get('is_vpn', False):
            risk_factors.append('vpn')
        
        if geolocation_data.get('is_proxy', False):
            risk_factors.append('proxy')
        
        if geolocation_data.get('is_tor', False):
            risk_factors.append('tor')
        
        if risk_factors:
            return {
                'risk_factors': risk_factors,
                'confidence': 0.6,
                'severity': 'medium',
                'details': geolocation_data,
            }
        
        return None
        
    except Exception as e:
        logger.error(f"Error checking network risk: {e}")
        return None


@shared_task
def determine_primary_reason(anomalies):
    """
    Determine primary reason from multiple anomalies.
    """
    if not anomalies:
        return 'unknown'
    
    # Prioritize certain anomaly types
    priority_order = [
        'scanner_detected',
        'multiple_failed_logins',
        'high_request_rate',
        'sensitive_path_access',
        'suspicious_country',
        'vpn_proxy_detected',
    ]
    
    for priority_type in priority_order:
        for anomaly in anomalies:
            if anomaly['type'] == priority_type:
                return priority_type
    
    # Return first anomaly type
    return anomalies[0]['type']


@shared_task
def send_anomaly_notification(anomalies):
    """
    Send notification for critical anomalies.
    """
    try:
        logger.warning(f"CRITICAL ANOMALIES DETECTED: {len(anomalies)}")
        
        for anomaly in anomalies:
            ip_address = anomaly['ip_address']
            severity = anomaly['severity']
            confidence = anomaly['confidence']
            request_count = anomaly['request_count']
            
            logger.warning(
                f"Critical anomaly: IP {ip_address} - "
                f"Severity: {severity}, Confidence: {confidence:.2f}, "
                f"Requests: {request_count}"
            )
        
        # Here you could implement email notifications, Slack webhooks, etc.
        # Example:
        # send_email_notification(anomalies)
        # send_slack_alert(anomalies)
        
        return {
            'status': 'success',
            'notifications_sent': len(anomalies),
        }
        
    except Exception as e:
        logger.error(f"Error sending anomaly notification: {e}")
        return {'status': 'error', 'error': str(e)}


@shared_task
def hourly_anomaly_detection():
    """
    Scheduled task to run anomaly detection hourly.
    """
    return detect_anomalies_task.delay()


@shared_task
def cleanup_old_detection_logs(days=30):
    """
    Clean up old anomaly detection logs.
    """
    try:
        cutoff_date = timezone.now() - timedelta(days=days)
        
        deleted_logs, _ = AnomalyDetectionLog.objects.filter(
            timestamp__lt=cutoff_date
        ).delete()
        
        deleted_suspicious, _ = SuspiciousIP.objects.filter(
            status__in=['resolved', 'false_positive'],
            updated_at__lt=cutoff_date
        ).delete()
        
        logger.info(f"Cleaned up {deleted_logs} old detection logs and {deleted_suspicious} resolved suspicious IPs")
        
        return {
            'deleted_logs': deleted_logs,
            'deleted_suspicious_ips': deleted_suspicious,
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up detection logs: {e}")
        return {'status': 'error', 'error': str(e)}


@shared_task
def real_time_anomaly_detection(request_data):
    """
    Real-time anomaly detection for immediate threat assessment.
    """
    try:
        ip_address = request_data.get('ip_address')
        path = request_data.get('path')
        user_agent = request_data.get('user_agent')
        method = request_data.get('method')
        
        # Check for immediate threats
        threats = []
        
        # Check for SQL injection patterns
        if detect_sql_injection(path, request_data.get('query_params', {})):
            threats.append({
                'type': 'sql_injection_pattern',
                'confidence': 0.9,
                'severity': 'critical',
            })
        
        # Check for XSS attempts
        if detect_xss_attempt(path, request_data.get('query_params', {}), user_agent):
            threats.append({
                'type': 'xss_attempt',
                'confidence': 0.8,
                'severity': 'critical',
            })
        
        # Check for path traversal
        if detect_path_traversal(path):
            threats.append({
                'type': 'path_traversal',
                'confidence': 0.7,
                'severity': 'high',
            })
        
        if threats:
            # Create immediate suspicious IP record
            with transaction.atomic():
                suspicious_ip = SuspiciousIP.get_or_create_suspicious_ip(
                    ip_address=ip_address,
                    reason=threats[0]['type'],
                    severity=threats[0]['severity'],
                    confidence=threats[0]['confidence']
                )
                
                # Auto-block for critical threats
                if threats[0]['severity'] == 'critical':
                    suspicious_ip.block_ip(duration_seconds=86400, notes="Auto-blocked for critical threat")
                
                # Log the detection
                AnomalyDetectionLog.objects.create(
                    ip_address=ip_address,
                    detection_type='real_time',
                    severity=threats[0]['severity'],
                    confidence_score=threats[0]['confidence'],
                    details={
                        'path': path,
                        'user_agent': user_agent,
                        'method': method,
                        'threats': threats,
                    },
                    triggered_rules=[t['type'] for t in threats]
                )
            
            return {
                'threat_detected': True,
                'threats': threats,
                'auto_blocked': threats[0]['severity'] == 'critical',
            }
        
        return {'threat_detected': False}
        
    except Exception as e:
        logger.error(f"Error in real-time anomaly detection: {e}")
        return {'status': 'error', 'error': str(e)}


def detect_sql_injection(path, query_params):
    """Detect SQL injection patterns"""
    sql_patterns = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' UNION SELECT",
        "SELECT * FROM",
        "INSERT INTO",
        "DROP TABLE",
        "DELETE FROM",
        "EXEC(",
        "EXECUTE(",
        "EXEC SP_",
        "EXEC XP_",
        "DECLARE @",
        "CAST(",
        "CONVERT(",
        "--",
        "/*",
        "*/",
        "@@",
        "CHAR(",
        "ASCII(",
    ]
    
    # Check path
    path_lower = path.lower()
    for pattern in sql_patterns:
        if pattern.lower() in path_lower:
            return True
    
    # Check query parameters
    for param_value in query_params.values():
        if isinstance(param_value, str):
            param_lower = param_value.lower()
            for pattern in sql_patterns:
                if pattern.lower() in param_lower:
                    return True
    
    return False


def detect_xss_attempt(path, query_params, user_agent):
    """Detect XSS attempt patterns"""
    xss_patterns = [
        "<script>",
        "</script>",
        "javascript:",
        "onload=",
        "onerror=",
        "onclick=",
        "onmouseover=",
        "alert(",
        "confirm(",
        "prompt(",
        "document.",
        "window.",
        "location.",
        "eval(",
        "setTimeout(",
        "setInterval(",
    ]
    
    # Check all inputs
    all_inputs = [path, user_agent] + list(query_params.values())
    
    for input_str in all_inputs:
        if isinstance(input_str, str):
            input_lower = input_str.lower()
            for pattern in xss_patterns:
                if pattern.lower() in input_lower:
                    return True
    
    return False


def detect_path_traversal(path):
    """Detect path traversal attempts"""
    traversal_patterns = [
        "../",
        "..\\",
        "/etc/passwd",
        "/etc/shadow",
        "C:\\Windows\\",
        "C:\\Program Files\\",
        "../../",
        "..\\..\\",
    ]
    
    path_lower = path.lower()
    for pattern in traversal_patterns:
        if pattern.lower() in path_lower:
            return True
    
    return False
