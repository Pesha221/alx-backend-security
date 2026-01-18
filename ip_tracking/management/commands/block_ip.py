# ip_tracking/management/commands/block_ip.py
from django.core.management.base import BaseCommand, CommandError
from django.contrib.auth import get_user_model
from ip_tracking.models import BlockedIP
from django.utils import timezone
from datetime import timedelta
import json
import sys

User = get_user_model()

class Command(BaseCommand):
    help = 'Add IP addresses to the blocklist'
    
    def add_arguments(self, parser):
        # Required arguments
        parser.add_argument(
            'ip_addresses',
            nargs='+',
            type=str,
            help='IP address(es) to block (space-separated)'
        )
        
        # Block options
        parser.add_argument(
            '--reason',
            type=str,
            required=True,
            help='Reason for blocking the IP'
        )
        
        parser.add_argument(
            '--type',
            type=str,
            choices=[choice[0] for choice in BlockedIP.BLOCK_TYPES],
            default='manual',
            help='Type of block'
        )
        
        parser.add_argument(
            '--duration',
            type=int,
            default=86400,
            help='Block duration in seconds (default: 86400 = 1 day)'
        )
        
        parser.add_argument(
            '--permanent',
            action='store_true',
            help='Make block permanent (overrides duration)'
        )
        
        parser.add_argument(
            '--subnet',
            type=int,
            choices=range(8, 33),
            help='Subnet mask for CIDR block (8-32)'
        )
        
        # User/Evidence options
        parser.add_argument(
            '--user',
            type=str,
            help='Username of admin creating the block'
        )
        
        parser.add_argument(
            '--evidence',
            type=str,
            help='JSON string with evidence data'
        )
        
        parser.add_argument(
            '--country',
            type=str,
            help='Country associated with IP'
        )
        
        parser.add_argument(
            '--isp',
            type=str,
            help='ISP associated with IP'
        )
        
        # Batch options
        parser.add_argument(
            '--file',
            type=str,
            help='File containing IP addresses to block (one per line)'
        )
        
        parser.add_argument(
            '--skip-existing',
            action='store_true',
            help='Skip IPs that are already blocked'
        )
        
        # Output options
        parser.add_argument(
            '--quiet',
            action='store_true',
            help='Suppress output except for errors'
        )
    
    def handle(self, *args, **options):
        ip_addresses = options['ip_addresses']
        reason = options['reason']
        block_type = options['type']
        duration = options['duration']
        is_permanent = options['permanent']
        subnet_mask = options['subnet']
        username = options['user']
        evidence_str = options['evidence']
        country = options['country']
        isp = options['isp']
        ip_file = options['file']
        skip_existing = options['skip_existing']
        quiet = options['quiet']
        
        # Get user if specified
        created_by = None
        if username:
            try:
                created_by = User.objects.get(username=username)
            except User.DoesNotExist:
                if not quiet:
                    self.stdout.write(self.style.WARNING(f"User '{username}' not found. Blocking without user association."))
        
        # Parse evidence JSON
        evidence = {}
        if evidence_str:
            try:
                evidence = json.loads(evidence_str)
            except json.JSONDecodeError:
                if not quiet:
                    self.stdout.write(self.style.WARNING(f"Invalid JSON in evidence. Using empty evidence."))
        
        # Read IPs from file if specified
        if ip_file:
            try:
                with open(ip_file, 'r') as f:
                    file_ips = [line.strip() for line in f if line.strip()]
                    ip_addresses.extend(file_ips)
                if not quiet:
                    self.stdout.write(f"Read {len(file_ips)} IP addresses from {ip_file}")
            except FileNotFoundError:
                raise CommandError(f"File not found: {ip_file}")
            except Exception as e:
                raise CommandError(f"Error reading file: {e}")
        
        # Remove duplicates
        ip_addresses = list(set(ip_addresses))
        
        if not quiet:
            self.stdout.write(f"Processing {len(ip_addresses)} unique IP addresses...")
        
        results = {
            'success': 0,
            'skipped': 0,
            'failed': 0,
            'details': []
        }
        
        # Block each IP
        for ip_address in ip_addresses:
            try:
                # Validate IP address
                if not self._validate_ip(ip_address):
                    if not quiet:
                        self.stdout.write(self.style.WARNING(f"Invalid IP address: {ip_address}"))
                    results['failed'] += 1
                    results['details'].append({
                        'ip': ip_address,
                        'status': 'failed',
                        'error': 'Invalid IP address'
                    })
                    continue
                
                # Check if already blocked
                existing_block = BlockedIP.objects.filter(ip_address=ip_address).first()
                if existing_block:
                    if skip_existing:
                        if not quiet:
                            self.stdout.write(self.style.WARNING(f"IP already blocked: {ip_address}"))
                        results['skipped'] += 1
                        results['details'].append({
                            'ip': ip_address,
                            'status': 'skipped',
                            'reason': 'Already blocked'
                        })
                        continue
                    else:
                        # Update existing block
                        existing_block.reason = reason
                        existing_block.block_type = block_type
                        existing_block.block_duration = duration
                        existing_block.is_permanent = is_permanent
                        existing_block.notes = f"Updated by block_ip command at {timezone.now()}"
                        existing_block.save()
                        
                        if not quiet:
                            self.stdout.write(self.style.SUCCESS(f"Updated existing block for IP: {ip_address}"))
                        results['success'] += 1
                        results['details'].append({
                            'ip': ip_address,
                            'status': 'updated',
                            'block_id': existing_block.id
                        })
                        continue
                
                # Prepare additional data
                additional_data = {}
                if country:
                    additional_data['country'] = country
                if isp:
                    additional_data['isp'] = isp
                if subnet_mask:
                    additional_data['subnet_mask'] = subnet_mask
                
                # Create block
                blocked_ip = BlockedIP.block_ip(
                    ip_address=ip_address,
                    reason=reason,
                    block_type=block_type,
                    duration=duration,
                    is_permanent=is_permanent,
                    created_by=created_by,
                    evidence=evidence,
                    **additional_data
                )
                
                if not quiet:
                    self.stdout.write(self.style.SUCCESS(f"Successfully blocked IP: {ip_address}"))
                results['success'] += 1
                results['details'].append({
                    'ip': ip_address,
                    'status': 'blocked',
                    'block_id': blocked_ip.id,
                    'block_type': block_type,
                    'duration': 'permanent' if is_permanent else f"{duration}s",
                })
                
            except Exception as e:
                if not quiet:
                    self.stdout.write(self.style.ERROR(f"Error blocking IP {ip_address}: {e}"))
                results['failed'] += 1
                results['details'].append({
                    'ip': ip_address,
                    'status': 'failed',
                    'error': str(e)
                })
        
        # Print summary
        if not quiet:
            self.stdout.write("\n" + "=" * 60)
            self.stdout.write("BLOCKING SUMMARY")
            self.stdout.write("=" * 60)
            self.stdout.write(f"Total IPs processed: {len(ip_addresses)}")
            self.stdout.write(f"Successfully blocked: {results['success']}")
            self.stdout.write(f"Skipped (already blocked): {results['skipped']}")
            self.stdout.write(f"Failed: {results['failed']}")
            
            if results['success'] > 0:
                self.stdout.write(self.style.SUCCESS("\n✓ Blocking completed successfully!"))
            elif results['failed'] > 0:
                self.stdout.write(self.style.ERROR("\n✗ Some IPs failed to block"))
        
        return results
    
    def _validate_ip(self, ip_address):
        """Validate IP address format"""
        try:
            from ipaddress import ip_address as validate_ip
            validate_ip(ip_address)
            return True
        except ValueError:
            # Check if it's CIDR notation
            try:
                from ipaddress import ip_network
                ip_network(ip_address, strict=False)
                return True
            except:
                return False
