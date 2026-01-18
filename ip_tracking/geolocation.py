# ip_tracking/geolocation.py
import logging
from django.core.cache import cache
from django.conf import settings
import requests
import json
import socket
from ipaddress import ip_address, IPv4Address
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class IPGeolocationService:
    """
    Service for IP address geolocation with caching.
    """
    
    # Service providers
    PROVIDERS = {
        'ipinfo': {
            'url': 'https://ipinfo.io/{ip}/json',
            'token': getattr(settings, 'IPINFO_TOKEN', None),
            'fields_mapping': {
                'ip': 'ip',
                'country': 'country_name',
                'country_code': 'country',
                'city': 'city',
                'region': 'region',
                'latitude': 'loc.split(",")[0]',
                'longitude': 'loc.split(",")[1]',
                'org': 'org',
                'timezone': 'timezone',
                'postal': 'postal',
            }
        },
        'ipapi': {
            'url': 'http://ip-api.com/json/{ip}',
            'fields_mapping': {
                'country': 'country',
                'country_code': 'countryCode',
                'city': 'city',
                'region': 'regionName',
                'latitude': 'lat',
                'longitude': 'lon',
                'isp': 'isp',
                'org': 'org',
                'asn': 'as',
                'timezone': 'timezone',
                'zip': 'zip',
            }
        },
        'ipgeolocation': {
            'url': 'https://api.ipgeolocation.io/ipgeo',
            'params': {'apiKey': getattr(settings, 'IPGEOLOCATION_API_KEY', None)},
            'fields_mapping': {
                'country': 'country_name',
                'country_code': 'country_code2',
                'city': 'city',
                'region': 'state_prov',
                'latitude': 'latitude',
                'longitude': 'longitude',
                'isp': 'isp',
                'organization': 'organization',
                'timezone': 'time_zone.name',
                'is_vpn': 'connection_type',
                'is_proxy': 'is_proxy',
            }
        }
    }
    
    @staticmethod
    def get_geolocation(ip: str, provider: str = None) -> dict:
        """
        Get geolocation data for an IP address with caching.
        
        Args:
            ip: IP address string
            provider: Service provider name (optional)
            
        Returns:
            Dictionary with geolocation data
        """
        # Validate IP address
        if not IPGeolocationService._is_valid_ip(ip):
            logger.warning(f"Invalid IP address: {ip}")
            return {}
        
        # Check cache first
        cache_key = f'ip_geolocation_{ip}'
        cached_data = cache.get(cache_key)
        
        if cached_data:
            logger.debug(f"Cache hit for IP: {ip}")
            return cached_data
        
        logger.debug(f"Cache miss for IP: {ip}, fetching from API...")
        
        # Get geolocation data from API
        geolocation_data = IPGeolocationService._fetch_geolocation(ip, provider)
        
        if geolocation_data:
            # Enhance with additional data
            geolocation_data = IPGeolocationService._enhance_geolocation_data(geolocation_data, ip)
            
            # Cache for 24 hours (86400 seconds)
            cache.set(cache_key, geolocation_data, timeout=86400)
            
            # Also cache reverse lookup
            country_cache_key = f'country_ips_{geolocation_data.get("country_code", "unknown")}'
            country_ips = cache.get(country_cache_key, [])
            if ip not in country_ips:
                country_ips.append(ip)
                cache.set(country_cache_key, country_ips, timeout=86400)
        
        return geolocation_data or {}
    
    @staticmethod
    def _is_valid_ip(ip: str) -> bool:
        """Validate IP address"""
        try:
            ip_address(ip)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def _fetch_geolocation(ip: str, provider: str = None) -> dict:
        """
        Fetch geolocation data from external API.
        
        Args:
            ip: IP address
            provider: Service provider name
            
        Returns:
            Geolocation data dictionary
        """
        # Use configured provider or default
        provider = provider or getattr(settings, 'IP_GEOLOCATION_PROVIDER', 'ipapi')
        
        if provider not in IPGeolocationService.PROVIDERS:
            logger.error(f"Unknown geolocation provider: {provider}")
            return {}
        
        provider_config = IPGeolocationService.PROVIDERS[provider]
        
        try:
            # Special handling for local/private IPs
            if IPGeolocationService._is_private_ip(ip):
                return IPGeolocationService._get_local_ip_data(ip)
            
            # Prepare request
            url = provider_config['url'].format(ip=ip)
            params = provider_config.get('params', {})
            headers = {
                'User-Agent': 'Django-IPGeolocation/1.0',
                'Accept': 'application/json',
            }
            
            # Add token if available
            if provider_config.get('token'):
                if 'ipinfo' in url:
                    params['token'] = provider_config['token']
            
            # Make request
            response = requests.get(url, params=params, headers=headers, timeout=5)
            response.raise_for_status()
            
            # Parse response
            data = response.json()
            
            # Transform data using mapping
            mapped_data = IPGeolocationService._map_response_data(data, provider_config['fields_mapping'])
            mapped_data['ip'] = ip
            mapped_data['provider'] = provider
            mapped_data['fetched_at'] = datetime.now().isoformat()
            
            return mapped_data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Error fetching geolocation for {ip}: {e}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing geolocation response for {ip}: {e}")
            return {}
    
    @staticmethod
    def _map_response_data(data: dict, mapping: dict) -> dict:
        """Map API response to standard format"""
        result = {}
        
        for target_field, source_field in mapping.items():
            try:
                # Handle complex mappings with eval (carefully)
                if isinstance(source_field, str) and 'split' in source_field:
                    # Special handling for loc field (latitude,longitude)
                    if 'loc.split' in source_field:
                        loc = data.get('loc', '')
                        if loc and ',' in loc:
                            lat, lon = loc.split(',')
                            result['latitude'] = float(lat.strip())
                            result['longitude'] = float(lon.strip())
                elif isinstance(source_field, str) and '.' in source_field:
                    # Handle nested fields
                    parts = source_field.split('.')
                    value = data
                    for part in parts:
                        value = value.get(part, {})
                    if value and value != {}:
                        result[target_field] = value
                else:
                    value = data.get(source_field)
                    if value is not None:
                        result[target_field] = value
            except (KeyError, AttributeError, ValueError):
                continue
        
        return result
    
    @staticmethod
    def _enhance_geolocation_data(data: dict, ip: str) -> dict:
        """Enhance geolocation data with additional information"""
        
        # Add security checks
        data['is_private'] = IPGeolocationService._is_private_ip(ip)
        data['is_reserved'] = IPGeolocationService._is_reserved_ip(ip)
        
        # Check for VPN/Proxy indicators
        org = data.get('org', '').lower()
        isp = data.get('isp', '').lower()
        
        vpn_indicators = ['vpn', 'proxy', 'anonymous', 'tor', 'hide', 'mask']
        hosting_indicators = ['digitalocean', 'linode', 'aws', 'google cloud', 'azure', 'vultr', 'ovh']
        
        data['is_vpn'] = any(indicator in org or indicator in isp for indicator in vpn_indicators)
        data['is_proxy'] = data.get('is_proxy', False)
        data['is_tor'] = data.get('is_tor', False)
        data['is_hosting'] = any(indicator in org or indicator in isp for indicator in hosting_indicators)
        
        # Add IP type
        try:
            ip_obj = ip_address(ip)
            data['ip_version'] = 'IPv4' if isinstance(ip_obj, IPv4Address) else 'IPv6'
        except:
            data['ip_version'] = 'Unknown'
        
        return data
    
    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """Check if IP is private/reserved"""
        try:
            ip_obj = ip_address(ip)
            return ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
        except:
            return False
    
    @staticmethod
    def _is_reserved_ip(ip: str) -> bool:
        """Check if IP is reserved"""
        try:
            ip_obj = ip_address(ip)
            return ip_obj.is_reserved or ip_obj.is_multicast
        except:
            return False
    
    @staticmethod
    def _get_local_ip_data(ip: str) -> dict:
        """Get data for local/private IPs"""
        return {
            'ip': ip,
            'country': 'Local Network',
            'country_code': 'LOCAL',
            'city': 'Local',
            'region': 'Internal Network',
            'is_private': True,
            'provider': 'local',
            'fetched_at': datetime.now().isoformat(),
        }
    
    @staticmethod
    def batch_lookup(ips: list) -> dict:
        """
        Perform batch geolocation lookup.
        
        Args:
            ips: List of IP addresses
            
        Returns:
            Dictionary mapping IPs to geolocation data
        """
        results = {}
        
        for ip in ips:
            data = IPGeolocationService.get_geolocation(ip)
            if data:
                results[ip] = data
        
        return results
    
    @staticmethod
    def get_cache_stats() -> dict:
        """Get cache statistics for geolocation"""
        try:
            # Count geolocation cache entries
            pattern = 'ip_geolocation_*'
            keys = cache.keys(pattern)
            
            # Analyze cache hits by country
            country_stats = {}
            for key in keys[:100]:  # Sample first 100
                data = cache.get(key)
                if data and 'country_code' in data:
                    country = data['country_code']
                    country_stats[country] = country_stats.get(country, 0) + 1
            
            return {
                'total_cached_ips': len(keys),
                'countries_cached': len(country_stats),
                'cache_size_sample': len(keys[:100]),
                'top_countries': dict(sorted(
                    country_stats.items(), 
                    key=lambda x: x[1], 
                    reverse=True
                )[:10]),
            }
        except:
            return {}
