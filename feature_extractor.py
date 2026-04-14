"""
Feature Extraction Module for Phishing Detection
Extracts 89 features from a URL for phishing detection
"""

import logging
import re
import socket
import ssl
import urllib.parse
import urllib.request
from datetime import datetime
import time
import threading

# Optional imports - handle gracefully if not available
try:
    import whois
except ImportError:
    whois = None

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    import requests
except ImportError:
    requests = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None

# Disable SSL warnings for requests
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)

class FeatureExtractor:
    CACHE_TTL_SECONDS = 3600  # 1 hour cache for expensive network calls
    # List of trusted domains
    TRUSTED_DOMAINS = set()
    PHISHING_DOMAINS = set()
    _cache_lock = threading.Lock()
    _whois_cache = {}
    _dns_cache = {}
    _html_cache = {}
    
    @classmethod
    def _load_trusted_domains(cls):
        """Load trusted domains from legitimateurls.csv"""
        if not cls.TRUSTED_DOMAINS:  # Only load once
            with open('DataFiles/legitimateurls.csv', 'r', encoding='utf-8') as f:
                # Read all non-empty lines and strip whitespace
                cls.TRUSTED_DOMAINS = {line.strip() for line in f if line.strip()}
    
    @classmethod
    def _load_phishing_domains(cls):
        """Load phishing URLs and domains from phishurls.csv"""
        if not cls.PHISHING_DOMAINS:  # Only load once
            with open('DataFiles/phishurls.csv', 'r', encoding='utf-8') as f:
                # Skip header and read all URLs
                next(f)  # Skip header
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            # Parse the URL
                            parsed = urllib.parse.urlparse(line)
                            if parsed.netloc:  # If URL has a netloc (domain)
                                # Store both the full URL and the domain
                                cls.PHISHING_DOMAINS.add(line.lower())  # Full URL
                                cls.PHISHING_DOMAINS.add(parsed.netloc.lower())  # Just the domain
                        except Exception as e:
                            print(f"Warning: Could not parse URL {line}: {e}")
    
    @classmethod
    def _get_cached_result(cls, cache, key):
        """Return cached value if still fresh."""
        with cls._cache_lock:
            record = cache.get(key)
            if not record:
                return None
            value, timestamp = record
            if time.time() - timestamp > cls.CACHE_TTL_SECONDS:
                cache.pop(key, None)
                return None
            return value

    @classmethod
    def _store_cached_result(cls, cache, key, value):
        """Persist value in cache with current timestamp."""
        with cls._cache_lock:
            cache[key] = (value, time.time())
    
    def __init__(self):
        self.features = {}
    
    def extract(self, url):
        """Backward-compatible single-URL extractor.
        Delegates to extract_all_features() to return the full feature dict.
        """
        return self.extract_all_features(url)
        
    def _is_trusted_domain(self, domain):
        """Check if domain is in the trusted domains list"""
        # Ensure trusted domains are loaded
        self._load_trusted_domains()
        
        domain = domain.lower()
        domain_parts = domain.split('.')
        # Check all possible domain variations (e.g., sub.domain.com, domain.com, com)
        for i in range(len(domain_parts)):
            test_domain = '.'.join(domain_parts[i:])
            if test_domain in self.TRUSTED_DOMAINS:
                return True
        return False
        
    def _is_phishing_domain(self, url):
        """
        Check if URL or its domain is in the phishing list
        
        Args:
            url: The URL to check (can be just a domain or full URL)
            
        Returns:
            bool: True if the URL or its domain is in the phishing list
        """
        # Ensure phishing domains are loaded
        self._load_phishing_domains()
        
        url = url.lower()
        
        # First check if the full URL is in our phishing list
        if url in self.PHISHING_DOMAINS:
            return True
            
        # If not, try to parse it as a URL and check the domain
        try:
            parsed = urllib.parse.urlparse(url)
            if not parsed.scheme:  # If it's just a domain without scheme
                domain = url
            else:
                domain = parsed.netloc
                
            # Check if the domain is in our phishing list
            if domain in self.PHISHING_DOMAINS:
                return True
                
            # Also check for subdomains
            domain_parts = domain.split('.')
            for i in range(1, len(domain_parts)):
                test_domain = '.'.join(domain_parts[i:])
                if test_domain in self.PHISHING_DOMAINS:
                    return True
        except Exception as e:
            print(f"Warning: Could not parse URL {url}: {e}")
            
        return False
            
    def extract_all_features(self, url):
        """Extract all 89 features from a URL"""
        try:
            # Parse URL
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc
            path = parsed.path
            scheme = parsed.scheme
            query = parsed.query
            fragment = parsed.fragment
            
            # Check if URL or domain is in whitelist
            if self._is_trusted_domain(domain):
                # Return all features as safe (0 for phishing indicators)
                features = self._get_default_features()
                # Set all phishing-related features to 0 (safe)
                for key in features:
                    if key not in ['length_url', 'length_hostname', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 'path_extension', 'length_words_raw', 'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw', 'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host', 'avg_word_path']:
                        features[key] = 0
                features['is_whitelisted'] = 1  # Add flag for whitelisted domains
                features['is_blacklisted'] = 0  # Make sure blacklisted flag is 0
                return features
                
            # Check if URL or domain is in phishing list
            if self._is_phishing_domain(url):  # Pass full URL for checking
                # Return all features as unsafe (1 for phishing indicators)
                features = self._get_default_features()
                # Set all phishing-related features to 1 (unsafe)
                for key in features:
                    if key not in ['length_url', 'length_hostname', 'nb_dots', 'nb_hyphens', 'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore', 'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma', 'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com', 'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url', 'ratio_digits_host', 'punycode', 'port', 'tld_in_path', 'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains', 'path_extension', 'length_words_raw', 'shortest_words_raw', 'shortest_word_host', 'shortest_word_path', 'longest_words_raw', 'longest_word_host', 'longest_word_path', 'avg_words_raw', 'avg_word_host', 'avg_word_path']:
                        features[key] = 1
                features['is_blacklisted'] = 1  # Add flag for blacklisted domains
                features['is_whitelisted'] = 0  # Make sure whitelisted flag is 0
                return features
            
            # Initialize all features with default values
            features = {
                # URL-based features
                'length_url': len(url),
                'length_hostname': len(domain),
                'ip': 1 if self._is_ip(domain) else 0,
                'nb_dots': url.count('.'),
                'nb_hyphens': url.count('-'),
                'nb_at': url.count('@'),
                'nb_qm': url.count('?'),
                'nb_and': url.count('&'),
                'nb_or': url.count('|'),
                'nb_eq': url.count('='),
                'nb_underscore': url.count('_'),
                'nb_tilde': url.count('~'),
                'nb_percent': url.count('%'),
                'nb_slash': url.count('/'),
                'nb_star': url.count('*'),
                'nb_colon': url.count(':'),
                'nb_comma': url.count(','),
                'nb_semicolumn': url.count(';'),
                'nb_dollar': url.count('$'),
                'nb_space': url.count(' '),
                'nb_www': 1 if 'www.' in domain else 0,
                'nb_com': 1 if domain.endswith('.com') else 0,
                'nb_dslash': url.count('//'),
                'http_in_path': 1 if 'http' in path.lower() else 0,
                'https_token': 1 if scheme == 'https' else 0,
                'ratio_digits_url': len(re.sub(r'[^0-9]', '', url)) / len(url) if url else 0,
                'ratio_digits_host': len(re.sub(r'[^0-9]', '', domain)) / len(domain) if domain else 0,
                'punycode': 1 if 'xn--' in domain else 0,
                'port': self._get_port(domain),
                'tld_in_path': 1 if any(tld in path.lower() for tld in ['.com', '.net', '.org']) else 0,
                'tld_in_subdomain': 1 if any(tld in domain.split('.')[0].lower() for tld in ['com', 'net', 'org']) else 0,
                'abnormal_subdomain': 1 if len(domain.split('.')) > 3 else 0,
                'nb_subdomains': len([x for x in domain.split('.') if x]) - 2 if '.' in domain else 0,
                'prefix_suffix': 1 if self._has_prefix_suffix(domain) else 0,
                'random_domain': 1 if self._is_random_domain(domain) else 0,
                'shortening_service': 1 if self._is_shortening_service(domain) else 0,
                'path_extension': 1 if '.' in path.split('/')[-1] else 0,
                'nb_redirection': 0,  # Will be updated if we can follow redirects
                'nb_external_redirection': 0,  # Will be updated if we can follow redirects
                'length_words_raw': len(re.findall(r'\w+', url)),
                'char_repeat': self._count_char_repeats(url),
                'shortest_words_raw': self._shortest_word_length(url),
                'shortest_word_host': self._shortest_word_length(domain),
                'shortest_word_path': self._shortest_word_length(path),
                'longest_words_raw': self._longest_word_length(url),
                'longest_word_host': self._longest_word_length(domain),
                'longest_word_path': self._longest_word_length(path),
                'avg_words_raw': self._avg_word_length(url),
                'avg_word_host': self._avg_word_length(domain),
                'avg_word_path': self._avg_word_length(path),
                'phish_hints': self._count_phish_hints(url, domain),
                'domain_in_brand': 0,  # Will be updated if we check against brand names
                'domain_registration_length': 1,  # Default, will try to get actual if possible
                'domain_age': 0,  # Will be updated if we can get whois info
                'web_traffic': 0,  # Would require external API
                'dns_record': 0,  # Will be updated if we can check DNS
                'google_index': 0,  # Would require Google API
                'page_rank': 0,  # Would require external service
                'external_favicon': 0,  # Will be updated if we can fetch the page
                'links_in_tags': 0,  # Will be updated if we can parse HTML
                'sfh': 0,  # Server Form Handler - will be updated
                'submit_email': 0,  # Will be updated if we find email forms
                'abnormal_url': 0,  # Will be updated based on URL structure
                'redirect': 0,  # Will be updated if we can follow redirects
                'on_mouseover': 0,  # Will be updated if we can parse JS
                'right_click': 0,  # Will be updated if we can parse JS
                'popup_window': 0,  # Will be updated if we can parse JS
                'iframe': 0,  # Will be updated if we can parse HTML
                'domain_with_copyright': 0,  # Will be updated if we can fetch the page
                'server_form_handler': 0,  # Will be updated if we can parse forms
                'info_email': 0,  # Will be updated if we find info@ emails
                'abnormal_url': 0,  # Will be updated based on URL structure
                'website_forwarding': 0,  # Will be updated if we can check redirects
                'status_bar_custom': 0,  # Will be updated if we can parse JS
                'disable_right_click': 0,  # Will be updated if we can detect this
                'using_popup_window': 0,  # Will be updated if we can parse JS
                'age_of_domain': 0,  # Will be updated if we can get whois info
                'dns_record': 0,  # Will be updated if we can check DNS
                'web_traffic': 0,  # Would require external API
                'page_rank': 0,  # Would require external service
                'google_index': 0,  # Would require Google API
                'links_pointing_to_page': 0,  # Would require external API
                'statistical_report': 0,  # Would require external analysis
                'tls_ssl_certificate': 1 if scheme == 'https' else 0,  # Simplified
                'url_anchor': 1 if '#' in url else 0,
                'url_anchor_percentage': len(fragment) / len(url) if url and '#' in url else 0,
                'ext_links': 0,  # Will be updated if we can parse HTML
                'int_links': 0,  # Will be updated if we can parse HTML
                'ext_favicon': 0,  # Will be updated if we can fetch the page
                'insecure_forms': 0,  # Will be updated if we can parse forms
                'relative_form_action': 0,  # Will be updated if we can parse forms
                'ext_form_action': 0,  # Will be updated if we can parse forms
                'abnormal_form_action': 0,  # Will be updated if we can parse forms
                'right_click_disabled': 0,  # Will be updated if we can detect this
                'using_iframe': 0,  # Will be updated if we can parse HTML
                'popup_window': 0,  # Will be updated if we can parse JS
                'onmouseover': 0,  # Will be updated if we can parse JS
                'right_clic': 0,  # Will be updated if we can detect this
                'empty_title': 0,  # Will be updated if we can fetch the page
                'domain_in_title': 0,  # Will be updated if we can fetch the page
                'domain_with_copyright': 0,  # Will be updated if we can fetch the page
                'whois_registered_domain': 0,  # Will be updated if we can get whois info
                'domain_registration_length': 1,  # Default, will try to get actual if possible
                'dns_record': 0,  # Will be updated if we can check DNS
                'google_index': 0,  # Would require Google API
                'page_rank': 0,  # Would require external service
            }
            
            # Try to fetch the page for HTML/JS based features
            try:
                if requests:
                    response = requests.get(url, timeout=10, verify=False, 
                                         headers={'User-Agent': 'Mozilla/5.0'})
                    if response.status_code == 200:
                        features.update(self._extract_html_features(response.text, url))
            except:
                pass
            
            # 12. RequestURL - HTTP in path
            features['http_in_path'] = 1 if 'http' in path.lower() else 0
            
            # 13. URL_of_Anchor - Safe anchor (default to 0)
            features['safe_anchor'] = 0  # Will be updated if we can fetch the page
            
            # 14. LinksInTags - Links in tags (default to 0)
            features['links_in_tags'] = 0  # Will be updated if we can fetch the page
            
            # 15. SFH - Server Form Handler (default to 0)
            features['sfh'] = 0  # Will be updated if we can fetch the page
            
            # 16. Submitting_to_email - Submit to email (default to 0)
            features['submit_email'] = 0  # Will be updated if we can fetch the page
            
            # 17. Abnormal_URL - Statistical report (default to 0)
            features['statistical_report'] = 0  # Default
            
            # 18. Redirect - Number of redirections
            features['nb_redirection'] = 0  # Will be updated if we can check
            
            # 19. HTML & JavaScript Features - OnMouseOver
            features['onmouseover'] = 0  # Will be updated if we can fetch the page
            
            # 20. RightClick - Right click disabled
            features['right_clic'] = 0  # Will be updated if we can fetch the page
            
            # 21. iFrame - Iframe usage
            features['iframe'] = 0  # Will be updated if we can fetch the page
            
            # 22. Popup - Popup window
            features['popup_window'] = 0  # Will be updated if we can fetch the page
            
            # 23. JS_Redirect - External redirections
            features['nb_external_redirection'] = 0  # Will be updated if we can fetch the page
            
            # 24. External_Resources - External hyperlinks ratio
            features['ratio_extHyperlinks'] = 0.0  # Will be updated if we can fetch the page
            
            # 25. Form_Action - Login form
            features['login_form'] = 0  # Will be updated if we can fetch the page
            
            # 26. Domain-Based - Domain in brand
            features['domain_in_brand'] = 0  # Default
            
            # 27. DomainAge - Domain age
            features['domain_age'] = -1  # Default, will try to get actual if possible
            
            # 28. DNSRecord - DNS record
            features['dns_record'] = 0  # Default, will try to check if possible
            
            # 29. WebTraffic - Web traffic (default to 0)
            features['web_traffic'] = 0  # Default
            
            # 30. GoogleIndex - Google index
            features['google_index'] = 0  # Default
            
            # Additional features needed for model
            features['length_hostname'] = len(domain)
            features['nb_dots'] = url.count('.')
            features['nb_hyphens'] = url.count('-')
            features['nb_qm'] = url.count('?')
            features['nb_and'] = url.count('&')
            features['nb_or'] = url.count('|')
            features['nb_eq'] = url.count('=')
            features['nb_underscore'] = url.count('_')
            features['nb_tilde'] = url.count('~')
            features['nb_percent'] = url.count('%')
            features['nb_slash'] = url.count('/')
            features['nb_star'] = url.count('*')
            features['nb_colon'] = url.count(':')
            features['nb_comma'] = url.count(',')
            features['nb_semicolumn'] = url.count(';')
            features['nb_dollar'] = url.count('$')
            features['nb_space'] = url.count(' ')
            features['nb_www'] = 1 if 'www' in domain.lower() else 0
            features['nb_com'] = 1 if '.com' in domain.lower() else 0
            features['nb_dslash'] = url.count('//')
            features['ratio_digits_url'] = len(re.findall(r'\d', url)) / len(url) if len(url) > 0 else 0
            features['ratio_digits_host'] = len(re.findall(r'\d', domain)) / len(domain) if len(domain) > 0 else 0
            features['punycode'] = 1 if 'xn--' in domain.lower() else 0
            features['tld_in_path'] = 1 if any(tld in path.lower() for tld in ['.com', '.org', '.net', '.edu']) else 0
            features['tld_in_subdomain'] = 1 if any(tld in domain.lower() for tld in ['.com', '.org', '.net', '.edu']) and domain.count('.') > 2 else 0
            features['abnormal_subdomain'] = 1 if domain.count('.') > 3 else 0
            features['random_domain'] = 0
            features['path_extension'] = 1 if '.' in path.split('/')[-1] and len(path.split('/')[-1].split('.')) > 1 else 0
            features['length_words_raw'] = len(re.findall(r'\b\w+\b', url))
            features['char_repeat'] = self._count_char_repeat(url)
            words = re.findall(r'\b\w+\b', url)
            features['shortest_words_raw'] = min([len(w) for w in words]) if words else 0
            host_words = re.findall(r'\b\w+\b', domain)
            features['shortest_word_host'] = min([len(w) for w in host_words]) if host_words else 0
            path_words = re.findall(r'\b\w+\b', path)
            features['shortest_word_path'] = min([len(w) for w in path_words]) if path_words else 0
            features['longest_words_raw'] = max([len(w) for w in words]) if words else 0
            features['longest_word_host'] = max([len(w) for w in host_words]) if host_words else 0
            features['longest_word_path'] = max([len(w) for w in path_words]) if path_words else 0
            features['avg_words_raw'] = sum([len(w) for w in words]) / len(words) if words else 0
            features['avg_word_host'] = sum([len(w) for w in host_words]) / len(host_words) if host_words else 0
            features['avg_word_path'] = sum([len(w) for w in path_words]) / len(path_words) if path_words else 0
            features['brand_in_subdomain'] = 0
            features['brand_in_path'] = 0
            features['suspecious_tld'] = 0
            features['nb_hyperlinks'] = 0
            features['ratio_intHyperlinks'] = 0.0
            features['ratio_nullHyperlinks'] = 0.0
            features['nb_extCSS'] = 0
            features['ratio_intRedirection'] = 0.0
            features['ratio_extRedirection'] = 0.0
            features['ratio_intErrors'] = 0.0
            features['ratio_extErrors'] = 0.0
            features['ratio_intMedia'] = 0.0
            features['ratio_extMedia'] = 0.0
            features['empty_title'] = 0
            features['domain_in_title'] = 0
            features['domain_with_copyright'] = 0
            features['whois_registered_domain'] = 0
            features['page_rank'] = 0
            
            # Try to fetch page content for HTML-based features
            if requests and BeautifulSoup:
                try:
                    self._extract_html_features(url, features, domain)
                except:
                    pass  # If we can't fetch, keep defaults
            
            # Try to get domain age and registration info
            if whois:
                try:
                    self._extract_domain_info(domain, features)
                except:
                    pass  # If we can't get info, keep defaults
            
            # Try to check DNS record
            if dns:
                try:
                    self._check_dns(domain, features)
                except:
                    pass  # If we can't check, keep defaults
            
            return features
            
        except Exception as e:
            print(f"Error extracting features: {e}")
            # Return default features with zeros
            return self._get_default_features()
    
    def _get_port(self, domain):
        """Extract port number from domain if specified"""
        if ':' in domain:
            try:
                port = int(domain.split(':')[-1])
                return port
            except (ValueError, IndexError):
                return 0
        return 0
        
    def _is_ip(self, domain):
        """Check if domain is an IP address"""
        try:
            socket.inet_aton(domain)
            return 1
        except (socket.error, UnicodeError):
            return 0
    
    def _is_shortening_service(self, domain):
        """Check if domain is a URL shortening service"""
        shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 
                     'buff.ly', 'adf.ly', 'bc.vc', 'shorte.st', 'v.gd', 'tr.im']
        return any(shortener in domain.lower() for shortener in shorteners)
    
    def _is_random_domain(self, domain):
        """Check if domain appears to be randomly generated"""
        # Check for random-looking strings (e.g., jd7d8f9d8f)
        if re.search(r'[a-f0-9]{8,}', domain):
            return 1
            
        # Check for repeated patterns that might indicate randomness
        if re.search(r'(\w{2,})\1{2,}', domain):
            return 1
            
        # Check for domains with random-looking subdomains
        subdomains = domain.split('.')
        for sub in subdomains[:-2]:  # Skip main domain and TLD
            if len(sub) > 10 and sum(c.isdigit() for c in sub) > len(sub)/2:
                return 1
                
        return 0
        
    def _has_prefix_suffix(self, domain):
        """Check if domain has prefix or suffix"""
        domain_clean = domain.split(':')[0].split('/')[0]
        return '-' in domain_clean
    
    def _count_char_repeats(self, text):
        """Count the maximum number of times any character is repeated consecutively"""
        if not text:
            return 0
            
        max_repeats = 1
        current_char = text[0]
        current_count = 1
        
        for char in text[1:]:
            if char == current_char:
                current_count += 1
                if current_count > max_repeats:
                    max_repeats = current_count
            else:
                current_char = char
                current_count = 1
                
        return max_repeats
        
    def _shortest_word_length(self, text):
        """Find the length of the shortest word in the text"""
        words = re.findall(r'\b\w+\b', text)
        if not words:
            return 0
        return min(len(word) for word in words)
        
    def _longest_word_length(self, text):
        """Find the length of the longest word in the text"""
        words = re.findall(r'\b\w+\b', text)
        if not words:
            return 0
        return max(len(word) for word in words)
        
    def _avg_word_length(self, text):
        """Calculate the average length of words in the text"""
        words = re.findall(r'\b\w+\b', text)
        if not words:
            return 0
        return sum(len(word) for word in words) / len(words)
        
    def _count_phish_hints(self, url, domain):
        """Count phishing hints in URL"""
        hints = ['verify', 'update', 'secure', 'account', 'suspended', 'limited', 
                'confirm', 'urgent', 'action', 'required', 'login', 'bank']
        count = sum(1 for hint in hints if hint in url.lower())
        return min(count, 1)  # Return 1 if any hint found, 0 otherwise
    
    def _count_char_repeat(self, url):
        """Count character repetitions"""
        max_repeat = 0
        for char in set(url):
            count = url.count(char)
            if count > max_repeat:
                max_repeat = count
        return max_repeat
    
    def _extract_html_features(self, url, features, domain):
        """Extract features from HTML content with lightweight caching."""
        if not requests or BeautifulSoup is None:
            return  # HTML inspection unavailable in this environment

        cache_key = f"{domain.lower()}::{url}"
        cached = self._get_cached_result(self._html_cache, cache_key)
        if cached is not None:
            features.update(cached)
            return

        updates = {}

        def _set_feature(key, value):
            features[key] = value
            updates[key] = value

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get(
                url,
                headers=headers,
                timeout=5,
                verify=False,
                allow_redirects=True,
            )
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'html.parser')

            # Check for favicon
            favicon_tags = soup.find_all('link', rel=['icon', 'shortcut icon'])
            if favicon_tags:
                for tag in favicon_tags:
                    href = tag.get('href', '')
                    if href and domain not in href:
                        _set_feature('external_favicon', 1)
                        break

            # Check for safe anchor
            anchors = soup.find_all('a', href=True)
            if anchors:
                safe_count = sum(1 for a in anchors if domain in (a.get('href') or ''))
                _set_feature('safe_anchor', 1 if safe_count > len(anchors) * 0.5 else 0)

            # Links in tags
            _set_feature('links_in_tags', len(soup.find_all(['script', 'link', 'style'], src=True)))

            # Check for form action
            forms = soup.find_all('form')
            if forms:
                _set_feature('login_form', 1)
                for form in forms:
                    action = (form.get('action') or '').lower()
                    if 'mailto:' in action or '@' in action:
                        _set_feature('submit_email', 1)
                        break

            # Check SFH
            for form in forms:
                action = form.get('action', '')
                if action and (action == 'about:blank' or action == '' or domain not in action):
                    _set_feature('sfh', 1)
                    break

            # Check for onmouseover
            if soup.find_all(attrs={'onmouseover': True}):
                _set_feature('onmouseover', 1)

            # Check for right click disable
            scripts = soup.find_all('script')
            for script in scripts:
                script_text = (script.string or '').lower()
                if 'contextmenu' in script_text or 'event.button' in script_text:
                    _set_feature('right_clic', 1)
                    break

            # Check for iframe
            if soup.find_all('iframe'):
                _set_feature('iframe', 1)

            # Check for popup
            for script in scripts:
                script_text = (script.string or '').lower()
                if 'popup' in script_text or 'window.open' in script_text:
                    _set_feature('popup_window', 1)
                    break

            # Count hyperlinks
            all_links = soup.find_all('a', href=True)
            _set_feature('nb_hyperlinks', len(all_links))

            if all_links:
                internal = sum(1 for link in all_links if domain in (link.get('href') or ''))
                external = len(all_links) - internal
                total_links = len(all_links)
                _set_feature('ratio_extHyperlinks', external / total_links if total_links > 0 else 0)
                _set_feature('ratio_intHyperlinks', internal / total_links if total_links > 0 else 0)
                null_links = sum(
                    1 for link in all_links if not link.get('href') or link.get('href') == '#'
                )
                _set_feature('ratio_nullHyperlinks', null_links / total_links if total_links > 0 else 0)

            # Check redirects
            if response.history:
                _set_feature('nb_redirection', len(response.history))
                _set_feature(
                    'nb_external_redirection',
                    sum(1 for h in response.history if domain not in h.url),
                )

        except Exception as exc:
            # Network errors are common; rely on defaults but record the issue for observability
            logger.warning("HTML feature extraction failed for %s: %s", url, exc)
        finally:
            self._store_cached_result(self._html_cache, cache_key, updates)
    
    def _extract_domain_info(self, domain, features):
        """Extract domain registration and age information (cached)."""
        if not whois:
            return

        domain_clean = domain.split(':')[0].split('/')[0].lower()
        cached = self._get_cached_result(self._whois_cache, domain_clean)
        if cached is not None:
            features.update(cached)
            return

        updates = {}
        try:
            w = whois.whois(domain_clean)

            creation_date = None
            if w.creation_date:
                creation_date = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date

            if creation_date:
                age_days = (datetime.now() - creation_date).days
                updates['domain_age'] = age_days
                updates['domain_registration_length'] = 1 if age_days > 365 else 0

            if w.registrar:
                updates['whois_registered_domain'] = 1
        except Exception as exc:
            # Some registries return mixed aware/naive datetimes; ignore those quietly.
            message = str(exc).lower()
            if "offset-naive and offset-aware" not in message:
                logger.warning("WHOIS lookup failed for %s: %s", domain_clean, exc)
        finally:
            features.update(updates)
            self._store_cached_result(self._whois_cache, domain_clean, updates)
    
    def _check_dns(self, domain, features):
        """Check DNS records with caching to avoid redundant lookups."""
        if not dns:
            return

        domain_clean = domain.split(':')[0].split('/')[0].lower()
        cached = self._get_cached_result(self._dns_cache, domain_clean)
        if cached is not None:
            features.update(cached)
            return

        updates = {}
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            answers = resolver.resolve(domain_clean, 'A')
            if answers:
                updates['dns_record'] = 1
        except Exception as exc:
            message = str(exc).lower()
            if "timed out" not in message:
                logger.warning("DNS lookup failed for %s: %s", domain_clean, exc)
        finally:
            if 'dns_record' not in updates:
                updates['dns_record'] = features.get('dns_record', 0)
            features.update(updates)
            self._store_cached_result(self._dns_cache, domain_clean, updates)
    
    def _get_default_features(self):
        """Return default feature values"""
        return {
            'ip': 0, 'length_url': 0, 'length_hostname': 0, 'nb_dots': 0, 'nb_hyphens': 0,
            'nb_at': 0, 'nb_qm': 0, 'nb_and': 0, 'nb_or': 0, 'nb_eq': 0, 'nb_underscore': 0,
            'nb_tilde': 0, 'nb_percent': 0, 'nb_slash': 0, 'nb_star': 0, 'nb_colon': 0,
            'nb_comma': 0, 'nb_semicolumn': 0, 'nb_dollar': 0, 'nb_space': 0, 'nb_www': 0,
            'nb_com': 0, 'nb_dslash': 0, 'http_in_path': 0, 'https_token': 0,
            'ratio_digits_url': 0.0, 'ratio_digits_host': 0.0, 'punycode': 0, 'port': 0,
            'tld_in_path': 0, 'tld_in_subdomain': 0, 'abnormal_subdomain': 0,
            'nb_subdomains': 0, 'prefix_suffix': 0, 'random_domain': 0, 'shortening_service': 0,
            'path_extension': 0, 'nb_redirection': 0, 'nb_external_redirection': 0,
            'length_words_raw': 0, 'char_repeat': 0, 'shortest_words_raw': 0,
            'shortest_word_host': 0, 'shortest_word_path': 0, 'longest_words_raw': 0,
            'longest_word_host': 0, 'longest_word_path': 0, 'avg_words_raw': 0.0,
            'avg_word_host': 0.0, 'avg_word_path': 0.0, 'phish_hints': 0,
            'domain_in_brand': 0, 'brand_in_subdomain': 0, 'brand_in_path': 0,
            'suspecious_tld': 0, 'statistical_report': 0, 'nb_hyperlinks': 0,
            'ratio_intHyperlinks': 0.0, 'ratio_extHyperlinks': 0.0, 'ratio_nullHyperlinks': 0.0,
            'nb_extCSS': 0, 'ratio_intRedirection': 0.0, 'ratio_extRedirection': 0.0,
            'ratio_intErrors': 0.0, 'ratio_extErrors': 0.0, 'login_form': 0,
            'external_favicon': 0, 'links_in_tags': 0, 'submit_email': 0,
            'ratio_intMedia': 0.0, 'ratio_extMedia': 0.0, 'sfh': 0, 'iframe': 0,
            'popup_window': 0, 'safe_anchor': 0, 'onmouseover': 0, 'right_clic': 0,
            'empty_title': 0, 'domain_in_title': 0, 'domain_with_copyright': 0,
            'whois_registered_domain': 0, 'domain_registration_length': 0,
            'domain_age': -1, 'web_traffic': 0, 'dns_record': 0, 'google_index': 0,
            'page_rank': 0
        }
