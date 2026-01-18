# ip_tracking/management/commands/unblock_ip.py
from django.core.management.base import BaseCommand
from ip_tracking.models import BlockedIP

class Command(BaseCommand):
    help = 'Remove IP addresses from the blocklist'
    
    def add_arguments(self, parser):
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='IP address(es) to unblock'
        )
        
        parser.add_argument(
            '--all',
            action='store_true',
            help='Unblock all IP addresses'
        )
        
        parser.add_argument(
            '--expired',
            action='store_true',
            help='Remove only expired temporary blocks'
        )
        
        parser.add_argument(
            '--type',
            type=str,
            choices=[choice[0] for choice in BlockedIP.BLOCK_TYPES],
            help='Unblock only IPs of specific type'
        )
    
    def handle(self, *args, **options):
        ip_addresses = options['ip_addresses']
        unblock_all = options['all']
        expired_only = options['expired']
        block_type = options['type']
        
        if unblock_all:
            # Confirm dangerous operation
            confirm = input("Are you sure you want to unblock ALL IP addresses? (yes/no): ")
            if confirm.lower() != 'yes':
                self.stdout.write(self.style.WARNING("Operation cancelled"))
                return
            
            query = BlockedIP.objects.all()
            if block_type:
                query = query.filter(block_type=block_type)
            
            count = query.count()
            query.delete()
            self.stdout.write(self.style.SUCCESS(f"Unblocked all {count} IP addresses"))
            return
        
        if expired_only:
            count = BlockedIP.cleanup_expired_blocks()
            self.stdout.write(self.style.SUCCESS(f"Removed {count} expired blocks"))
            return
        
        # Unblock specific IPs
        unblocked_count = 0
        
        for ip_address in ip_addresses:
            try:
                blocked_ips = BlockedIP.objects.filter(ip_address=ip_address)
                
                if block_type:
                    blocked_ips = blocked_ips.filter(block_type=block_type)
                
                count = blocked_ips.count()
                blocked_ips.delete()
                
                if count > 0:
                    self.stdout.write(self.style.SUCCESS(f"Unblocked IP: {ip_address}"))
                    unblocked_count += count
                else:
                    self.stdout.write(self.style.WARNING(f"IP not found or already unblocked: {ip_address}"))
                    
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"Error unblocking IP {ip_address}: {e}"))
        
        self.stdout.write(self.style.SUCCESS(f"\nSuccessfully unblocked {unblocked_count} IP addresses"))
        
