import re
import tldextract

def extract_features(url):
    features = []

    # Feature 1: Length of URL
    features.append(len(url))

    # Feature 2: Uses '@'
    features.append(1 if '@' in url else 0)

    # Feature 3: Too many subdomains
    features.append(1 if url.count('.') > 3 else 0)

    # Feature 4: Uses HTTPS
    features.append(1 if url.startswith('https') else 0)

    # Feature 5: Suspicious keywords
    keywords = ['secure', 'login', 'signin', 'bank', 'update']
    features.append(1 if any(k in url.lower() for k in keywords) else 0)

    return features
