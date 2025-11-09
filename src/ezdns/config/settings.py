"""Application configuration and settings."""

import os
from typing import List, Optional
from pathlib import Path


class Settings:
    """Application configuration settings."""

    VERSION = '2.0.0'
    APP_NAME = 'ezdns-toolkit'

    DNS_TIMEOUT = 5.0
    DNS_LIFETIME = 10.0
    DNS_RETRIES = 3
    DNS_NAMESERVERS: Optional[List[str]] = None

    WHOIS_TIMEOUT = 10.0
    WHOIS_RETRIES = 2

    IP_DETECTION_TIMEOUT = 5.0
    IP_DETECTION_SERVICES = [
        'https://api.ipify.org?format=json',
        'https://ifconfig.me/ip',
        'https://icanhazip.com',
    ]

    DEFAULT_OUTPUT_FORMAT = 'text'
    COLOR_OUTPUT = True
    VERBOSE = False

    ENABLE_CACHE = False
    CACHE_TTL = 300
    CACHE_DIR = Path.home() / '.cache' / 'ezdns'

    LOG_LEVEL = 'INFO'
    LOG_FILE: Optional[Path] = None
    LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'

    VERIFY_SSL = True
    MAX_DOMAIN_LENGTH = 253
    MAX_QUERY_BATCH = 100

    RATE_LIMIT_ENABLED = False
    RATE_LIMIT_CALLS = 10
    RATE_LIMIT_PERIOD = 60

    @classmethod
    def from_env(cls) -> 'Settings':
        """Load settings from environment variables.

        Returns:
            Settings instance with values from environment
        """
        settings = cls()

        if os.getenv('EZDNS_DNS_TIMEOUT'):
            settings.DNS_TIMEOUT = float(os.getenv('EZDNS_DNS_TIMEOUT'))

        if os.getenv('EZDNS_VERBOSE'):
            settings.VERBOSE = os.getenv('EZDNS_VERBOSE').lower() in ('true', '1', 'yes')

        if os.getenv('EZDNS_LOG_LEVEL'):
            settings.LOG_LEVEL = os.getenv('EZDNS_LOG_LEVEL').upper()

        if os.getenv('EZDNS_OUTPUT_FORMAT'):
            settings.DEFAULT_OUTPUT_FORMAT = os.getenv('EZDNS_OUTPUT_FORMAT').lower()

        if os.getenv('EZDNS_NO_COLOR'):
            settings.COLOR_OUTPUT = False

        if os.getenv('EZDNS_CACHE_ENABLED'):
            settings.ENABLE_CACHE = os.getenv('EZDNS_CACHE_ENABLED').lower() in ('true', '1', 'yes')

        return settings

    def validate(self) -> None:
        """Validate configuration settings.

        Raises:
            ValueError: If any setting is invalid
        """
        if self.DNS_TIMEOUT <= 0:
            raise ValueError('DNS_TIMEOUT must be positive')

        if self.DNS_RETRIES < 0:
            raise ValueError('DNS_RETRIES cannot be negative')

        if self.DEFAULT_OUTPUT_FORMAT not in ('text', 'json', 'csv', 'yaml'):
            raise ValueError(f'Invalid output format: {self.DEFAULT_OUTPUT_FORMAT}')

        if self.LOG_LEVEL not in ('DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'):
            raise ValueError(f'Invalid log level: {self.LOG_LEVEL}')

        if self.MAX_QUERY_BATCH <= 0:
            raise ValueError('MAX_QUERY_BATCH must be positive')


# Global settings instance
settings = Settings.from_env()
