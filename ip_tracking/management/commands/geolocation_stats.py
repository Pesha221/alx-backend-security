# ip_tracking/management/commands/geolocation_stats.py
from django.core.management.base import BaseCommand
from django.db.models import Count
from ip_tracking.models import RequestLog
from ip_tracking.geolocation import IPGeolocationService
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Show geolocation statistics for request logs'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=7,
            help='Number of days to analyze'
        )
        parser.add_argument(
            '--top',
            type=int,
            default=10,
            help='Number of top countries/cities to show'
        )
        parser.add_argument(
            '--cache-stats',
            action='store_true',
            help='Show cache statistics'
        )
    
    def handle(self, *args, **options):
        days = options['days']
        top_n = options['top']
        
        if options['cache_stats']:
            self._show_cache_stats()
            return
        
        self.stdout.write(self.style.SUCCESS(f"Geolocation Statistics (Last {days} days)"))
        self.stdout.write("=" * 60)
        
        # Import here to avoid circular imports
        from django.utils import timezone
        from datetime import timedelta
        
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Country statistics
        self.stdout.write("\n🌍 Top Countries:")
        country_stats = RequestLog.objects.filter(
            timestamp__gte=cutoff_date,
            country__isnull=False
        ).values('country', 'country_code').annotate(
            count=Count('id')
        ).order_by('-count')[:top_n]
        
        for stat in country_stats:
            self.stdout.write(
                f"  {stat['country']} ({stat['country_code']}): "
                f"{stat['count']} requests"
            )
        
        # City statistics
        self.stdout.write("\n🏙️  Top Cities:")
        city_stats = RequestLog.objects.filter(
            timestamp__gte=cutoff_date,
            city__isnull=False
        ).values('city', 'country').annotate(
            count=Count('id')
        ).order_by('-count')[:top_n]
        
        for stat in city_stats:
            self.stdout.write(
                f"  {stat['city']}, {stat['country']}: "
                f"{stat['count']} requests"
            )
        
        # Suspicious activity
        self.stdout.write("\n🚨 Suspicious Activity:")
        suspicious = RequestLog.objects.filter(
            timestamp__gte=cutoff_date
        ).filter(
            is_vpn=True | is_proxy=True | is_tor=True | is_hosting=True
        ).count()
        
        self.stdout.write(f"  Total suspicious requests: {suspicious}")
        
        # Cache statistics
        self.stdout.write("\n💾 Cache Statistics:")
        cache_stats = IPGeolocationService.get_cache_stats()
        self.stdout.write(f"  Cached IPs: {cache_stats.get('total_cached_ips', 0)}")
        self.stdout.write(f"  Countries in cache: {cache_stats.get('countries_cached', 0)}")
        
        self.stdout.write("\n" + "=" * 60)
    
    def _show_cache_stats(self):
        """Show detailed cache statistics"""
        cache_stats = IPGeolocationService.get_cache_stats()
        
        self.stdout.write(self.style.SUCCESS("Geolocation Cache Statistics"))
        self.stdout.write("=" * 60)
        
        self.stdout.write(f"Total cached IPs: {cache_stats.get('total_cached_ips', 0)}")
        self.stdout.write(f"Countries in cache: {cache_stats.get('countries_cached', 0)}")
        
        if 'top_countries' in cache_stats:
            self.stdout.write("\nTop countries in cache:")
            for country, count in cache_stats['top_countries'].items():
                self.stdout.write(f"  {country}: {count} IPs")
        
        self.stdout.write("\n" + "=" * 60)

# ip_tracking/management/commands/update_geolocation.py
from django.core.management.base import BaseCommand
from ip_tracking.models import RequestLog
from ip_tracking.geolocation import IPGeolocationService
from django.db import transaction
import logging

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Update geolocation data for existing request logs'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--limit',
            type=int,
            default=100,
            help='Number of logs to update'
        )
        parser.add_argument(
            '--ip',
            type=str,
            help='Update specific IP address'
        )
        parser.add_argument(
            '--clear-cache',
            action='store_true',
            help='Clear geolocation cache before updating'
        )
    
    def handle(self, *args, **options):
        limit = options['limit']
        specific_ip = options['ip']
        
        if options['clear_cache']:
            self._clear_geolocation_cache()
        
        if specific_ip:
            self._update_single_ip(specific_ip)
        else:
            self._update_batch(limit)
    
    def _update_single_ip(self, ip):
        """Update geolocation for a single IP"""
        self.stdout.write(f"Updating geolocation for IP: {ip}")
        
        # Get fresh geolocation data
        geolocation_data = IPGeolocationService.get_geolocation(ip)
        
        if not geolocation_data:
            self.stdout.write(self.style.ERROR(f"No geolocation data for {ip}"))
            return
        
        # Update all logs for this IP
        logs = RequestLog.objects.filter(ip_address=ip, country__isnull=True)
        count = logs.count()
        
        self.stdout.write(f"Found {count} logs for IP {ip}")
        
        updated = 0
        for log in logs:
            try:
                log.save_geolocation_data(geolocation_data)
                updated += 1
            except Exception as e:
                logger.error(f"Error updating log {log.id}: {e}")
        
        self.stdout.write(
            self.style.SUCCESS(f"Updated {updated} logs for IP {ip}")
        )
    
    def _update_batch(self, limit):
        """Update geolocation for a batch of logs"""
        self.stdout.write(f"Updating geolocation for up to {limit} logs...")
        
        # Find logs without geolocation data
        logs = RequestLog.objects.filter(
            country__isnull=True
        ).distinct('ip_address')[:limit]
        
        total_updated = 0
        
        for log in logs:
            try:
                # Get geolocation data
                geolocation_data = IPGeolocationService.get_geolocation(log.ip_address)
                
                if geolocation_data:
                    # Update this specific log
                    log.save_geolocation_data(geolocation_data)
                    total_updated += 1
                    
                    # Also update other logs with same IP
                    other_logs = RequestLog.objects.filter(
                        ip_address=log.ip_address,
                        country__isnull=True
                    ).exclude(id=log.id)
                    
                    for other_log in other_logs:
                        other_log.save_geolocation_data(geolocation_data)
                        total_updated += 1
                    
                    self.stdout.write(f"  Updated IP {log.ip_address}")
                    
            except Exception as e:
                logger.error(f"Error processing IP {log.ip_address}: {e}")
        
        self.stdout.write(
            self.style.SUCCESS(f"Updated {total_updated} logs total")
        )
    
    def _clear_geolocation_cache(self):
        """Clear geolocation cache"""
        try:
            # Clear all geolocation cache keys
            pattern = 'ip_geolocation_*'
            keys = cache.keys(pattern)
            
            if keys:
                cache.delete_many(keys)
                self.stdout.write(
                    self.style.SUCCESS(f"Cleared {len(keys)} cache entries")
                )
            else:
                self.stdout.write("No cache entries to clear")
                
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error clearing cache: {e}"))
