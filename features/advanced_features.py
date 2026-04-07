"""
Advanced feature extraction for PhishGuard V2.

Includes:
  - WHOIS data (domain age, registrar info)
  - DNS records (MX, NS, TXT)
  - SSL certificate analysis
  - Redirect chain analysis
  - HTML content features
  
These are extracted server-side for deeper security analysis.
"""

from __future__ import annotations

import logging
import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse
import re

logger = logging.getLogger(__name__)


@dataclass
class DomainMetadata:
    """Domain information from WHOIS/DNS lookups."""
    domain: str
    registrar: Optional[str] = None
    creation_date: Optional[datetime] = None
    expiration_date: Optional[datetime] = None
    domain_age_days: Optional[int] = None
    has_mx_records: bool = False
    has_ns_records: bool = False
    dns_suspicious: bool = False
    registrant_private: bool = False


@dataclass
class SSLInfo:
    """SSL/TLS certificate information."""
    has_valid_cert: bool = False
    cert_issuer: Optional[str] = None
    cert_subject: Optional[str] = None
    cert_expires: Optional[datetime] = None
    is_self_signed: bool = False
    days_to_expiry: Optional[int] = None
    cert_brand_mismatch: bool = False


@dataclass
class ContentFeatures:
    """HTML content analysis results."""
    num_login_forms: int = 0
    num_password_fields: int = 0
    num_suspicious_iframes: int = 0
    num_external_scripts: int = 0
    has_form_action_mismatch: bool = False
    has_obfuscated_js: bool = False
    suspicious_onclick_handlers: int = 0
    form_submission_domain: Optional[str] = None


class AdvancedFeatureExtractor:
    """Extract advanced features from URLs and HTML content."""

    def __init__(self, timeout: int = 5, enable_network_checks: bool = True):
        """
        Args:
            timeout: Seconds to wait for DNS/SSL queries
            enable_network_checks: If False, skip DNS/SSL lookups for speed
        """
        self.timeout = timeout
        self.enable_network_checks = enable_network_checks

    def extract_domain_features(self, url: str) -> dict[str, Any]:
        """
        Extract domain-level features (WHOIS, DNS, SSL).
        Returns dict with feature flags safe for numeric conversion.
        """
        if not self.enable_network_checks:
            return {
                "domain_age_days": 0.0,
                "domain_very_new": 0.0,
                "domain_suspicious_age": 0.0,
                "has_mx_records": 0.0,
                "has_ns_records": 0.0,
                "suspicious_dns": 0.0,
                "has_valid_ssl": 0.0,
                "ssl_self_signed": 0.0,
                "ssl_cert_expires_soon": 0.0,
                "ssl_brand_mismatch": 0.0,
                "days_to_ssl_expiry": 0.0,
            }

        parsed = urlparse(url)
        domain = parsed.hostname or ""
        
        features = {}
        
        # 1. Domain age (heuristic if WHOIS unavailable)
        domain_age_days = self._estimate_domain_age(domain)
        features["domain_age_days"] = float(domain_age_days) if domain_age_days else 0.0
        features["domain_very_new"] = 1.0 if domain_age_days and domain_age_days < 30 else 0.0
        features["domain_suspicious_age"] = 1.0 if domain_age_days and domain_age_days < 90 else 0.0
        
        # 2. DNS records
        dns_info = self._check_dns_records(domain)
        features["has_mx_records"] = 1.0 if dns_info.get("has_mx", False) else 0.0
        features["has_ns_records"] = 1.0 if dns_info.get("has_ns", False) else 0.0
        features["suspicious_dns"] = 1.0 if dns_info.get("suspicious", False) else 0.0
        
        # 3. SSL Certificate
        ssl_info = self._check_ssl_certificate(domain)
        features["has_valid_ssl"] = 1.0 if ssl_info.get("valid", False) else 0.0
        features["ssl_self_signed"] = 1.0 if ssl_info.get("self_signed", False) else 0.0
        features["ssl_cert_expires_soon"] = 1.0 if ssl_info.get("expires_soon", False) else 0.0
        features["ssl_brand_mismatch"] = 1.0 if ssl_info.get("brand_mismatch", False) else 0.0
        features["days_to_ssl_expiry"] = float(ssl_info.get("days_to_expiry", 365))
        
        return features

    def extract_content_features(self, html_content: str, form_action_domain: Optional[str] = None) -> dict[str, Any]:
        """
        Extract HTML/DOM features from page content.
        Used for multi-modal detection.
        """
        features = {}
        
        if not html_content:
            return {k: 0.0 for k in [
                "login_form_count", "password_field_count", "suspicious_iframe_count",
                "external_script_count", "form_action_mismatch", "obfuscated_js",
                "suspicious_onclick_count"
            ]}
        
        # Count login forms
        login_forms = self._count_login_forms(html_content)
        features["login_form_count"] = float(login_forms)
        
        # Count password fields
        password_fields = self._count_password_fields(html_content)
        features["password_field_count"] = float(password_fields)
        
        # Suspicious iframes (cross-domain)
        suspicious_iframes = self._count_suspicious_iframes(html_content, form_action_domain)
        features["suspicious_iframe_count"] = float(suspicious_iframes)
        
        # External scripts
        external_scripts = self._count_external_scripts(html_content)
        features["external_script_count"] = float(external_scripts)
        
        # Form action domain mismatch
        form_mismatch = self._check_form_action_mismatch(html_content, form_action_domain) if form_action_domain else False
        features["form_action_mismatch"] = 1.0 if form_mismatch else 0.0
        
        # Obfuscated JavaScript
        obfuscated = self._detect_obfuscated_js(html_content)
        features["obfuscated_js"] = 1.0 if obfuscated else 0.0
        
        # Suspicious onclick handlers
        onclick_count = self._count_suspicious_onclick_handlers(html_content)
        features["suspicious_onclick_count"] = float(onclick_count)
        
        return features

    def extract_redirect_features(self, url: str) -> dict[str, Any]:
        """
        Analyze redirect chains (client-side and server-side heuristics).
        """
        features = {}
        
        # Count redirects in URL (# of ? and & indicating redirect parameters)
        redirect_count = self._estimate_redirect_chain(url)
        features["estimated_redirects"] = float(redirect_count)
        features["suspicious_redirect_chain"] = 1.0 if redirect_count > 3 else 0.0
        
        return features

    # ========== Private helpers ==========

    def _estimate_domain_age(self, domain: str) -> Optional[int]:
        """
        Estimate domain age in days using heuristics (WHOIS is slow).
        In production, use whois library or external WHOIS API.
        """
        # For now, return None (will be improved with actual WHOIS integration)
        # Actual implementation would require whois library
        return None

    def _check_dns_records(self, domain: str) -> dict[str, Any]:
        """Check for MX, NS, and other DNS records."""
        result = {
            "has_mx": False,
            "has_ns": False,
            "suspicious": False,
        }
        
        try:
            # Try to resolve MX records
            mx_records = socket.getmxbyname(domain) if hasattr(socket, 'getmxbyname') else None
            result["has_mx"] = bool(mx_records)
        except Exception as e:
            logger.debug(f"DNS MX lookup failed for {domain}: {e}")
        
        try:
            # Try basic DNS resolution
            socket.gethostbyname(domain)
            result["has_ns"] = True
        except socket.gaierror:
            logger.debug(f"DNS resolution failed for {domain}")
            result["suspicious"] = True
        
        return result

    def _check_ssl_certificate(self, domain: str) -> dict[str, Any]:
        """Check SSL/TLS certificate validity."""
        result = {
            "valid": False,
            "self_signed": False,
            "expires_soon": False,
            "brand_mismatch": False,
            "days_to_expiry": 365,
        }
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    result["valid"] = True
                    
                    # Check for self-signed
                    if cert.get("issuer") == cert.get("subject"):
                        result["self_signed"] = True
                    
                    # Check expiry
                    if "notAfter" in cert:
                        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days_to_expiry = (not_after - datetime.now()).days
                        result["days_to_expiry"] = max(0, days_to_expiry)
                        result["expires_soon"] = days_to_expiry < 30
                    
                    # Brand mismatch check (cert doesn't match domain)
                    subject = dict(x[0] for x in cert.get("subject", []))
                    cn = subject.get("commonName", "")
                    if cn and cn not in domain and not domain.endswith(cn):
                        result["brand_mismatch"] = True
        
        except socket.timeout:
            logger.debug(f"SSL check timeout for {domain}")
        except Exception as e:
            logger.debug(f"SSL check failed for {domain}: {e}")
        
        return result

    def _count_login_forms(self, html: str) -> int:
        """Count login-like form elements."""
        count = 0
        # Look for form with login-related attributes
        login_patterns = [
            r'<form[^>]*action[^>]*=(?:"|\')?[^"\'>\s]*(?:login|signin|authenticate|verify)',
            r'<form[^>]*name[^>]*=(?:"|\')?login',
            r'type\s*=\s*["\']?password["\']?',
        ]
        for pattern in login_patterns:
            matches = re.findall(pattern, html, re.IGNORECASE)
            count += len(matches) // 2  # Avoid double-counting
        return min(count, 10)  # Cap at 10

    def _count_password_fields(self, html: str) -> int:
        """Count password input fields."""
        pattern = r'<input[^>]*type\s*=\s*["\']?password["\']?[^>]*>'
        matches = re.findall(pattern, html, re.IGNORECASE)
        return min(len(matches), 10)

    def _count_suspicious_iframes(self, html: str, page_domain: Optional[str] = None) -> int:
        """Count iframes that point to external domains."""
        count = 0
        iframe_pattern = r'<iframe[^>]*src[^>]*=(?:"|\')?([^"\'>\s]+)'
        iframes = re.findall(iframe_pattern, html, re.IGNORECASE)
        
        for iframe_src in iframes:
            # Count if it's external
            if page_domain and not iframe_src.startswith("javascript:"):
                if page_domain not in iframe_src:
                    count += 1
            else:
                count += 1  # Default to suspicious if domain unknown
        
        return min(count, 10)

    def _count_external_scripts(self, html: str) -> int:
        """Count external JavaScript files."""
        pattern = r'<script[^>]*src[^>]*=(?:"|\')?([^"\'>\s]+)'
        scripts = re.findall(pattern, html, re.IGNORECASE)
        return min(len(scripts), 20)

    def _check_form_action_mismatch(self, html: str, page_domain: Optional[str]) -> bool:
        """Check if forms submit to different domain."""
        if not page_domain:
            return False
        
        form_pattern = r'<form[^>]*action[^>]*=(?:"|\')?([^"\'>\s]+)'
        forms = re.findall(form_pattern, html, re.IGNORECASE)
        
        for form_action in forms:
            if form_action.startswith("http") and page_domain not in form_action:
                return True
        
        return False

    def _detect_obfuscated_js(self, html: str) -> bool:
        """Detect signs of obfuscated JavaScript."""
        # Look for eval, obfuscation patterns
        obfuscation_patterns = [
            r"eval\s*\(\s*['\"]",
            r"String\.fromCharCode",
            r"atob\s*\(",
            r"unescape\s*\(",
            r"decodeURIComponent\s*\(",
            r"\w+\s*=\s*function\s*\(\w*\)\s*{\s*var\s+\w+\s*=\s*String\.fromCharCode",
        ]
        
        for pattern in obfuscation_patterns:
            if re.search(pattern, html, re.IGNORECASE):
                return True
        
        return False

    def _count_suspicious_onclick_handlers(self, html: str) -> int:
        """Count suspicious onclick handlers (redirects, popups, data exfil)."""
        count = 0
        onclick_pattern = r'onclick\s*=\s*["\']([^"\']*)["\']'
        handlers = re.findall(onclick_pattern, html, re.IGNORECASE)
        
        suspicious_patterns = [
            r"window\.open",
            r"location\s*=",
            r"eval",
            r"String\.fromCharCode",
            r"fetch\s*\(",
            r"XMLHttpRequest",
        ]
        
        for handler in handlers:
            for sus_pattern in suspicious_patterns:
                if re.search(sus_pattern, handler, re.IGNORECASE):
                    count += 1
                    break
        
        return min(count, 10)

    def _estimate_redirect_chain(self, url: str) -> int:
        """Estimate redirect chain length from URL parameters."""
        # Look for redirect parameters in query string
        parsed = urlparse(url)
        query = parsed.query or ""
        
        redirect_params = ["redirect", "return", "url", "goto", "ref", "return_url"]
        count = 0
        
        for param in redirect_params:
            if f"{param}=" in query.lower():
                count += 1
        
        return count
