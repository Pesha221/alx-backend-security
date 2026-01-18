# test_ip_logging.py
import os
import sys
import django
import requests
from datetime import datetime, timedelta

# Setup Django
sys.path.append('/home/peshawar/alx-backend-caching_property_listings')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'alx_backend_caching_property_listings.settings')
django.setup()

from ip_tracking.models import RequestLog
from django.utils import timezone

def test_ip_logging():
    """Test the IP logging middleware"""
    print("=" * 60)
    print("Testing IP Logging Middleware")
    print("=" * 60)
    
    # Get initial count
    initial_count = RequestLog.objects.count()
    print(f"\n📊 Initial log count: {initial_count}")
    
    # Make test requests
    base_url = "http://localhost:8000"
    
    test_endpoints = [
        "/ip-tracking/test/",
        "/properties/",
        "/admin/",  # Might redirect to login
    ]
    
    print("\n📤 Making test requests...")
    for endpoint in test_endpoints:
        try:
            response = requests.get(f"{base_url}{endpoint}", timeout=5)
            print(f"  {endpoint}: {response.status_code}")
        except Exception as e:
            print(f"  {endpoint}: Error - {e}")
    
    # Wait a moment for logging to complete
    import time
    time.sleep(2)
    
    # Check new logs
    new_count = RequestLog.objects.count()
    added_logs = new_count - initial_count
    
    print(f"\n📈 New logs added: {added_logs}")
    
    if added_logs > 0:
        print("✅ IP logging is working!")
        
        # Show recent logs
        print("\n📋 Recent logs:")
        recent_logs = RequestLog.objects.order_by('-timestamp')[:5]
        
        for i, log in enumerate(recent_logs, 1):
            print(f"\n  Log {i}:")
            print(f"    IP: {log.ip_address}")
            print(f"    Path: {log.path}")
            print(f"    Method: {log.method}")
            print(f"    Time: {log.timestamp.strftime('%H:%M:%S')}")
            print(f"    User: {log.user.username if log.user else 'Anonymous'}")
            
    else:
        print("❌ No new logs found. Check middleware configuration.")
    
    # Show statistics
    print("\n📊 Statistics:")
    print(f"  Total logs: {new_count}")
    
    # Count by method
    from django.db.models import Count
    methods = RequestLog.objects.values('method').annotate(count=Count('id'))
    for method in methods:
        print(f"  {method['method']}: {method['count']}")
    
    # Count by status code
    status_codes = RequestLog.objects.exclude(status_code__isnull=True).values('status_code').annotate(count=Count('id')).order_by('-count')[:5]
    print("\n  Top status codes:")
    for status in status_codes:
        print(f"    {status['status_code']}: {status['count']}")
    
    print("\n" + "=" * 60)
    print("Test Complete!")
    print("=" * 60)
    
    # Instructions
    print("\n🔧 Next steps:")
    print("1. Visit: http://localhost:8000/ip-tracking/logs/ to view logs")
    print("2. Visit: http://localhost:8000/admin/ip_tracking/requestlog/ for admin view")
    print("3. Make more requests to see logging in action")
    print("4. Check console/logs for any middleware errors")

def cleanup_old_logs():
    """Clean up logs older than 1 hour for testing"""
    from django.utils import timezone
    from datetime import timedelta
    
    one_hour_ago = timezone.now() - timedelta(hours=1)
    old_logs = RequestLog.objects.filter(timestamp__lt=one_hour_ago)
    count = old_logs.count()
    
    if count > 0:
        old_logs.delete()
        print(f"🧹 Cleaned up {count} logs older than 1 hour")
    else:
        print("🧹 No old logs to clean up")

if __name__ == "__main__":
    # Make sure Django server is running
    print("Make sure Django server is running on http://localhost:8000")
    print("Run: python manage.py runserver")
    print()
    
    input("Press Enter to start testing...")
    
    # Clean up old test logs
    cleanup_old_logs()
    
    # Run test
    test_ip_logging()
