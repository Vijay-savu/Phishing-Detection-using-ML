import re
import numpy as np
from urllib.parse import urlparse

def extract_features(url: str) -> np.ndarray:
    """
    Extract 25 consistent numeric features from a URL.
    Works safely even if the URL is malformed.
    """

    # Handle empty or malformed input
    if not url or not isinstance(url, str):
        return np.zeros(25)

    try:
        parsed = urlparse(url)
    except Exception:
        return np.zeros(25)

    # --- Basic URL parts ---
    hostname = parsed.netloc or ''
    path = parsed.path or ''
    query = parsed.query or ''

    # --- Feature extraction ---
    length_url = len(url)
    length_hostname = len(hostname)
    nb_dots = url.count('.')
    nb_hyphens = url.count('-')
    nb_at = url.count('@')
    nb_qm = url.count('?')
    nb_and = url.count('&')
    nb_eq = url.count('=')
    nb_underscore = url.count('_')
    nb_percent = url.count('%')
    nb_slash = url.count('/')
    nb_colon = url.count(':')
    nb_digits = sum(c.isdigit() for c in url)
    ratio_digits = nb_digits / length_url if length_url > 0 else 0
    ratio_letters = sum(c.isalpha() for c in url) / length_url if length_url > 0 else 0

    # Presence-based flags
    has_https = 1 if 'https' in parsed.scheme else 0
    has_ip = 1 if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", hostname) else 0
    has_www = 1 if 'www.' in hostname else 0
    tld_len = len(hostname.split('.')[-1]) if '.' in hostname else 0
    num_subdomains = len(hostname.split('.')) - 2 if hostname.count('.') >= 2 else 0
    path_depth = len([p for p in path.split('/') if p])
    query_length = len(query)
    contains_login = 1 if 'login' in url.lower() else 0
    contains_secure = 1 if 'secure' in url.lower() else 0
    contains_free = 1 if 'free' in url.lower() else 0

    # --- Final feature vector (25 values) ---
    features = np.array([
        length_url, length_hostname, nb_dots, nb_hyphens, nb_at,
        nb_qm, nb_and, nb_eq, nb_underscore, nb_percent,
        nb_slash, nb_colon, nb_digits, ratio_digits, ratio_letters,
        has_https, has_ip, has_www, tld_len, num_subdomains,
        path_depth, query_length, contains_login, contains_secure, contains_free
    ], dtype=float)

    return features
