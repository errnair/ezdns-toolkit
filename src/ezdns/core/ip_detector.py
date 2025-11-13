"""Public IP address detection using HTTPS."""

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

from ..config.settings import settings
from ..utils.exceptions import IPDetectionError, NetworkError

logger = logging.getLogger(__name__)


class IPDetector:
    """Handles public IP address detection with multiple fallback services."""

    def __init__(self, timeout: float = None):
        """Initialize IP detector."""
        self.timeout = timeout or settings.IP_DETECTION_TIMEOUT
        self.services = settings.IP_DETECTION_SERVICES

    def _looks_like_ip(self, text: str) -> bool:
        """Check if text looks like an IP address."""
        from ..utils.validators import is_ipv4, is_ipv6
        return is_ipv4(text) or is_ipv6(text)

    def _query_service(self, service_url: str) -> Optional[str]:
        """Query IP detection service."""
        try:
            logger.debug(f'Querying IP detection service: {service_url}')

            request = urllib.request.Request(
                service_url,
                headers={
                    'User-Agent': f'{settings.APP_NAME}/{settings.VERSION}',
                    'Accept': 'application/json, text/plain, */*',
                }
            )

            if settings.VERIFY_SSL:
                import ssl
                context = ssl.create_default_context()
            else:
                import ssl
                context = ssl._create_unverified_context()
                logger.warning('SSL verification is disabled - this is insecure!')

            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                content = response.read().decode('utf-8').strip()

                try:
                    data = json.loads(content)
                    if 'ip' in data:
                        return data['ip']
                    elif 'YourFuckingIPAddress' in data:
                        return data['YourFuckingIPAddress']
                    else:
                        return list(data.values())[0] if data else None
                except json.JSONDecodeError:
                    # Treat as plain text response, but validate it looks like an IP
                    if content and self._looks_like_ip(content):
                        return content
                    return None

        except urllib.error.HTTPError as e:
            logger.debug(f'HTTP error from {service_url}: {e.code} {e.reason}')
            return None
        except urllib.error.URLError as e:
            logger.debug(f'URL error from {service_url}: {e.reason}')
            return None
        except TimeoutError:
            logger.debug(f'Timeout querying {service_url}')
            return None
        except Exception as e:
            logger.debug(f'Unexpected error from {service_url}: {type(e).__name__}: {e}')
            return None

    def detect_ip(self) -> str:
        """Detect public IP address."""
        last_error = None

        for service_url in self.services:
            try:
                ip_address = self._query_service(service_url)
                if ip_address:
                    logger.info(f'Successfully detected IP: {ip_address} (via {service_url})')
                    return ip_address
            except Exception as e:
                last_error = e
                logger.debug(f'Service {service_url} failed: {e}')
                continue

        error_msg = 'All IP detection services failed'
        if last_error:
            error_msg += f'. Last error: {last_error}'

        logger.error(error_msg)
        raise IPDetectionError(
            service='multiple services',
            reason='All configured services failed to respond'
        )


def get_public_ip(timeout: float = None) -> str:
    """Detect public IP address."""
    detector = IPDetector(timeout=timeout)
    return detector.detect_ip()
