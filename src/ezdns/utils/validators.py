"""Input validation for domain names and IP addresses."""

import re
from typing import Tuple
from .exceptions import InvalidDomainError


# RFC 1035 compliant domain validation patterns
DOMAIN_LABEL_PATTERN = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)
DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"  # Total length must be 1-253 characters
    r"(?!-)"  # Cannot start with hyphen
    r"([a-z0-9-]{1,63}\.)*"  # Subdomains
    r"[a-z0-9-]{1,63}"  # TLD
    r"(?<!-)$",  # Cannot end with hyphen
    re.IGNORECASE,
)

# Maximum lengths per RFC specifications
MAX_DOMAIN_LENGTH = 253
MAX_LABEL_LENGTH = 63
MIN_DOMAIN_LENGTH = 2


def is_valid_domain_label(label: str) -> bool:
    """Validate domain label."""
    if not label or len(label) > MAX_LABEL_LENGTH:
        return False

    return bool(DOMAIN_LABEL_PATTERN.match(label))


def is_valid_domain(domain: str) -> bool:
    """Check if domain is valid per RFC 1035."""
    if not domain or not isinstance(domain, str):
        return False

    domain = domain.strip().lower()

    if domain.endswith("."):
        domain = domain[:-1]

    if len(domain) < MIN_DOMAIN_LENGTH or len(domain) > MAX_DOMAIN_LENGTH:
        return False

    if not DOMAIN_PATTERN.match(domain):
        return False

    labels = domain.split(".")
    if not labels or len(labels) < 2:
        return False

    return all(is_valid_domain_label(label) for label in labels)


def validate_domain(domain: str, allow_subdomain: bool = True) -> str:
    """Validate and normalize domain name."""
    if not domain:
        raise InvalidDomainError(domain or "", "Domain name cannot be empty")

    if not isinstance(domain, str):
        raise InvalidDomainError(str(domain), "Domain must be a string")

    domain = domain.strip().lower()

    if "://" in domain:
        domain = domain.split("://", 1)[1]

    if "/" in domain:
        domain = domain.split("/", 1)[0]

    if ":" in domain:
        domain = domain.split(":", 1)[0]

    if domain.endswith("."):
        domain = domain[:-1]

    if "\x00" in domain:
        raise InvalidDomainError(domain, "Domain contains null bytes")

    if any(ord(char) < 32 or ord(char) == 127 for char in domain):
        raise InvalidDomainError(domain, "Domain contains control characters")

    dangerous_chars = ["<", ">", '"', "'", "`", "\\", "|", ";", "&", "$", "(", ")"]
    if any(char in domain for char in dangerous_chars):
        raise InvalidDomainError(domain, "Domain contains invalid characters")

    if len(domain) < MIN_DOMAIN_LENGTH:
        raise InvalidDomainError(
            domain, f"Domain too short (minimum {MIN_DOMAIN_LENGTH} characters)"
        )

    if len(domain) > MAX_DOMAIN_LENGTH:
        raise InvalidDomainError(
            domain, f"Domain too long (maximum {MAX_DOMAIN_LENGTH} characters)"
        )

    if not DOMAIN_PATTERN.match(domain):
        raise InvalidDomainError(domain, "Domain does not match RFC 1035 format")

    labels = domain.split(".")
    if len(labels) < 2:
        raise InvalidDomainError(domain, "Domain must have at least two labels (e.g., example.com)")

    for i, label in enumerate(labels):
        if not is_valid_domain_label(label):
            raise InvalidDomainError(domain, f'Invalid label "{label}" at position {i + 1}')

    return domain


def validate_domain_with_subdomain(domain: str) -> Tuple[str, bool]:
    """Validate domain and check if subdomain."""
    normalized = validate_domain(domain, allow_subdomain=True)

    labels = normalized.split(".")
    is_subdomain = len(labels) > 2

    return normalized, is_subdomain


def sanitize_input(value: str, max_length: int = 1000) -> str:
    """Sanitize string input."""
    if not isinstance(value, str):
        raise ValueError("Input must be a string")

    value = value.replace("\x00", "")
    value = value.strip()

    if len(value) > max_length:
        raise ValueError(f"Input too long (maximum {max_length} characters)")

    return value


def is_ipv4(address: str) -> bool:
    """Check if valid IPv4 address."""
    if not address:
        return False

    parts = address.split(".")
    if len(parts) != 4:
        return False

    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False


def is_ipv6(address: str) -> bool:
    """Check if valid IPv6 address."""
    if not address:
        return False

    # Check for invalid patterns
    if address.startswith(":::") or address.endswith(":::"):
        return False

    if "::" in address:
        parts = address.split("::")
        if len(parts) > 2:
            return False
        # Check for empty parts caused by leading/trailing ::
        if parts[0] == "" and parts[1] == "":
            return False

    groups = address.replace("::", ":").split(":")
    if len(groups) > 8:
        return False

    try:
        for group in groups:
            if group:
                int(group, 16)
                if len(group) > 4:
                    return False
        return True
    except (ValueError, AttributeError):
        return False
