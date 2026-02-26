"""
app/utils/url_normalizer.py
─────────────────────────────────────────────────────────────
Robust URL canonicalization to prevent distribution mismatch between
functionally identical URLs (e.g. trailing slashes, fragments, case differences).
"""

import re
from urllib.parse import urlparse, urlunparse

def normalize_url(url: str) -> str:
    """
    Normalizes a URL to ensure consistent feature extraction and inference.
    
    Rules:
    - Strip leading/trailing whitespace
    - Lowercase scheme and netloc
    - Remove default ports (:80 for http, :443 for https)
    - Remove fragment (#section)
    - Remove trailing slash if path is only '/'
    - Preserve meaningful paths and query parameters
    
    Test cases Validation:
    Input:
    https://Example.com
    https://example.com/
    https://example.com:443/
    https://example.com#section
    
    Output (all same):
    https://example.com
    """
    if not url:
        return url
        
    url = url.strip()
    
    # Must have a scheme for urlparse to work correctly.
    # We prefix with http:// if missing, though the API Pydantic model
    # already demands a valid AnyHttpUrl.
    if not re.match(r'^[a-zA-Z0-9+.-]+://', url):
        if url.startswith('//'):
            url = 'http:' + url
        else:
            url = 'http://' + url

    try:
        parsed = urlparse(url)
    except Exception:
        # If unparseable by standard library, return as-is
        return url
        
    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()
    
    # Remove default ports from netloc
    if scheme == 'http' and netloc.endswith(':80'):
        netloc = netloc[:-3]
    elif scheme == 'https' and netloc.endswith(':443'):
        netloc = netloc[:-4]
        
    path = parsed.path
    # Remove trailing slash ONLY if it is the root path (just '/')
    # meaning the path is empty conceptually.
    if path == '/':
        path = ''
        
    # Reconstruct without fragment
    normalized = urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        ''  # Strip fragment completely
    ))
    
    return normalized
