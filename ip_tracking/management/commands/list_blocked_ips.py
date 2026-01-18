# ip_tracking/management/commands/list_blocked_ips.py
from django.core.management.base import BaseCommand
from django.utils import timezone
from ip_tracking.models import BlockedIP
from django.db.models import Count, Q

class Command(BaseCommand):
    help = 'List all blocked IP addresses'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--active',
            action='store_true',
            help='Show only active blocks'
        )
        
        parser.add_argument(
            '--type',
            type=str,
            help='Filter by block type'
        )
        
        parser.add_argument(
            '--country',
            type=str,
            help='Filter by country'
        )
        
        parser.add_argument(
            '--search',
            type=str,
            help='Search in IP address or reason'
        )
        
        parser.add_argument(
            '--limit',
            type=int,
            default=50,
            help='Limit number of results'
        )
        
        parser.add_argument(
            '--stats',
            action='store_true',
            help='Show statistics instead of list'
        )
        
        parser.add_argument(
            '--export',
            type=str,
            help='Export to file (csv or json)'
        )
    
    def handle(self, *args, **options):
        query = BlockedIP.objects.all()
        
        # Apply filters
        if options['active']:
            query = BlockedIP.get_active_blocks()
        
        if options['type']:
            query = query.filter(block_type=options['type'])
        
        if options['country']:
            query = query.filter(country__icontains=options['country'])
        
        if options['search']:
            query = query.filter(
                Q(ip_address__icontains=options['search']) |
                Q(reason__icontains=options['search'])
            )
        
        # Show statistics
        if options['stats']:
            self._show_statistics(query)
            return
        
        # Apply limit
        query = query.order_by('-blocked_at')[:options['limit']]
        
        # Export if requested
        if options['export']:
            self._export_data(query, options['export'])
            return
        
        # Display list
        self.stdout.write("=" * 100)
        self.stdout.write(f"{'IP Address':<20} {'Type':<15} {'Reason':<30} {'Blocked At':<20} {'Status':<10}")
        self.stdout.write("=" * 100)
        
        for block in query:
            status = "Active" if block.is_active else "Expired"
            
            # Truncate long reasons
            reason = block.reason
            if len(reason) > 28:
                reason = reason[:25] + "..."
            
            self.stdout.write(
                f"{block.ip_address:<20} "
                f"{block.get_block_type_display():<15} "
                f"{reason:<30} "
                f"{block.blocked_at.strftime('%Y-%m-%d %H:%M'):<20} "
                f"{status:<10}"
            )
        
        self.stdout.write("=" * 100)
        self.stdout.write(f"Total blocked IPs: {query.count()}")
        
        # Show summary
        active_count = BlockedIP.get_active_blocks().count()
        permanent_count = BlockedIP.objects.filter(is_permanent=True).count()
        
        self.stdout.write(f"Active blocks: {active_count}")
        self.stdout.write(f"Permanent blocks: {permanent_count}")
    
    def _show_statistics(self, query):
        """Display statistics about blocked IPs"""
        total = query.count()
        active = BlockedIP.get_active_blocks().count()
        
        # Count by type
        type_stats = query.values('block_type').annotate(
            count=Count('id')
        ).order_by('-count')
        
        # Count by country
        country_stats = query.exclude(country__isnull=True).values('country').annotate(
            count=Count('id')
        ).order_by('-count')[:10]
        
        self.stdout.write("=" * 60)
        self.stdout.write("BLOCKED IP STATISTICS")
        self.stdout.write("=" * 60)
        self.stdout.write(f"Total blocked IPs: {total}")
        self.stdout.write(f"Currently active: {active}")
        
        self.stdout.write("\nBlock Types:")
        for stat in type_stats:
            self.stdout.write(f"  {stat['block_type']}: {stat['count']}")
        
        self.stdout.write("\nTop Countries:")
        for stat in country_stats:
            self.stdout.write(f"  {stat['country']}: {stat['count']}")
        
        self.stdout.write("=" * 60)
    
    def _export_data(self, query, filename):
        """Export blocked IP data to file"""
        import csv
        import json
        
        data = list(query.values(
            'ip_address', 'block_type', 'reason', 
            'blocked_at', 'is_permanent', 'block_duration',
            'country', 'city', 'isp'
        ))
        
        if filename.endswith('.json'):
            with open(filename, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            self.stdout.write(self.style.SUCCESS(f"Exported {len(data)} records to {filename}"))
        
        elif filename.endswith('.csv'):
            with open(filename, 'w', newline='') as f:
                if data:
                    writer = csv.DictWriter(f, fieldnames=data[0].keys())
                    writer.writeheader()
                    writer.writerows(data)
            self.stdout.write(self.style.SUCCESS(f"Exported {len(data)} records to {filename}"))
        
        else:
            self.stdout.write(self.style.ERROR("Unsupported file format. Use .json or .csv"))
