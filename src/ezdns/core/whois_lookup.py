"""WHOIS domain information lookup."""

import logging
from typing import List, Dict, Optional
import whois as whois_lib

from ..config.settings import settings
from ..utils.exceptions import WHOISQueryError
from ..utils.validators import validate_domain

logger = logging.getLogger(__name__)


class WHOISLookup:
    """Handles WHOIS domain information queries."""

    def __init__(self, timeout: float = None):
        """Initialize WHOIS lookup handler."""
        self.timeout = timeout or settings.WHOIS_TIMEOUT

    def query(self, domain: str) -> Dict[str, any]:
        """Query WHOIS information for domain."""
        domain = validate_domain(domain)

        try:
            logger.debug(f'Querying WHOIS information for {domain}')
            whois_data = whois_lib.whois(domain)

            if not whois_data:
                raise WHOISQueryError(domain, 'No WHOIS data returned')

            logger.info(f'Successfully retrieved WHOIS data for {domain}')
            return self._parse_whois_data(whois_data)

        except WHOISQueryError:
            raise

        except Exception as e:
            logger.error(f'WHOIS query failed for {domain}: {e}')
            raise WHOISQueryError(domain, str(e))

    def _parse_whois_data(self, whois_data) -> Dict[str, any]:
        """Parse WHOIS data object into dictionary."""
        parsed = {}

        if hasattr(whois_data, 'name_servers') and whois_data.name_servers:
            ns_list = whois_data.name_servers
            if isinstance(ns_list, list):
                ns_list = [ns.lower() for ns in ns_list if ns]
                parsed['nameservers'] = list(dict.fromkeys(ns_list))
            else:
                parsed['nameservers'] = [str(ns_list).lower()]
        else:
            parsed['nameservers'] = []

        if hasattr(whois_data, 'registrar') and whois_data.registrar:
            parsed['registrar'] = str(whois_data.registrar)
        else:
            parsed['registrar'] = None

        if hasattr(whois_data, 'creation_date') and whois_data.creation_date:
            date = whois_data.creation_date
            if isinstance(date, list):
                date = date[0] if date else None
            parsed['creation_date'] = str(date) if date else None
        else:
            parsed['creation_date'] = None

        if hasattr(whois_data, 'expiration_date') and whois_data.expiration_date:
            date = whois_data.expiration_date
            if isinstance(date, list):
                date = date[0] if date else None
            parsed['expiration_date'] = str(date) if date else None
        else:
            parsed['expiration_date'] = None

        if hasattr(whois_data, 'updated_date') and whois_data.updated_date:
            date = whois_data.updated_date
            if isinstance(date, list):
                date = date[0] if date else None
            parsed['updated_date'] = str(date) if date else None
        else:
            parsed['updated_date'] = None

        if hasattr(whois_data, 'status') and whois_data.status:
            status = whois_data.status
            if isinstance(status, list):
                parsed['status'] = status
            else:
                parsed['status'] = [str(status)]
        else:
            parsed['status'] = []

        # Extract emails
        if hasattr(whois_data, 'emails') and whois_data.emails:
            emails = whois_data.emails
            if isinstance(emails, list):
                parsed['emails'] = emails
            else:
                parsed['emails'] = [str(emails)]
        else:
            parsed['emails'] = []

        # Extract registrant info (if available)
        if hasattr(whois_data, 'name') and whois_data.name:
            parsed['registrant_name'] = str(whois_data.name)
        else:
            parsed['registrant_name'] = None

        if hasattr(whois_data, 'org') and whois_data.org:
            parsed['registrant_org'] = str(whois_data.org)
        else:
            parsed['registrant_org'] = None

        return parsed

    def get_nameservers(self, domain: str) -> List[str]:
        """Get nameservers from WHOIS data."""
        whois_data = self.query(domain)
        return whois_data.get('nameservers', [])

    def get_registrar(self, domain: str) -> Optional[str]:
        """Get registrar from WHOIS data."""
        whois_data = self.query(domain)
        return whois_data.get('registrar')


def get_whois_info(domain: str, timeout: float = None) -> Dict[str, any]:
    """Get WHOIS information."""
    lookup = WHOISLookup(timeout=timeout)
    return lookup.query(domain)


def get_whois_nameservers(domain: str, timeout: float = None) -> List[str]:
    """Get nameservers from WHOIS."""
    lookup = WHOISLookup(timeout=timeout)
    return lookup.get_nameservers(domain)
