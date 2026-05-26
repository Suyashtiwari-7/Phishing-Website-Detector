import os
import sys
import joblib
import socket
import re
from datetime import datetime
from flask import Flask, request, render_template
import plotly.graph_objs as go
import plotly.io as pio
from features import extract_features

# ✅ Helper function to retrieve real-time domain registration age via WHOIS socket queries
def get_domain_age(url):
    domain = url.lower().strip()
    if domain.startswith("https://"):
        domain = domain[8:]
    elif domain.startswith("http://"):
        domain = domain[7:]
    
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]
    if domain.startswith("www."):
        domain = domain[4:]
        
    domain_match = re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z]{2,})$', domain)
    if not domain_match:
        return None, "invalid"
    
    root_domain = domain_match.group(1)
    tld = root_domain.split('.')[-1]
    
    if tld in ["com", "net"]:
        whois_server = "whois.verisign-grs.com"
    else:
        whois_server = "whois.iana.org"
        
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2.5) # Prevent blocking the Flask thread for more than 2.5s
        s.connect((whois_server, 43))
        
        if tld in ["com", "net"]:
            s.send(f"domain {root_domain}\r\n".encode())
        else:
            s.send(f"{root_domain}\r\n".encode())
            
        res = b""
        while True:
            d = s.recv(4096)
            if not d:
                break
            res += d
        s.close()
        text = res.decode('utf-8', errors='ignore')
        
        if "No match for" in text or "NOT FOUND" in text.upper() or "No entries found" in text:
            return None, "unregistered"
            
        date_match = re.search(r'(Creation Date|Created On|created|Registration Time):\s*(.+)', text, re.IGNORECASE)
        if date_match:
            date_str = date_match.group(2).strip()
            y_m_d = re.search(r'(\d{4}-\d{2}-\d{2})', date_str)
            if y_m_d:
                c_date = datetime.strptime(y_m_d.group(1), "%Y-%m-%d")
                age_days = (datetime.now() - c_date).days
                return age_days, c_date.strftime("%Y-%m-%d")
                
        return None, "unknown"
    except Exception:
        return None, "timeout"

# ✅ Helper function to scan active page content for credential harvesting forms & brand spoofing
def scan_page_content(url, domain):
    import requests
    target_url = url
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
        
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(target_url, headers=headers, timeout=2.0, allow_redirects=True)
        html = response.text
        html_lower = html.lower()
        
        # Check for password/credential inputs
        has_password = False
        if 'type="password"' in html_lower or 'type=\'password\'' in html_lower or 'name="password"' in html_lower or 'name="pass"' in html_lower:
            has_password = True
            
        # Check for brand spoofing (check <title> and main headings like <h1> or <h2>)
        # Fetch title tag content
        title_match = re.search(r'<title>(.*?)<\/title>', html, re.IGNORECASE)
        page_title = title_match.group(1).lower() if title_match else ""
        
        # Fetch all h1 and h2 headers text
        headings_text = " ".join(re.findall(r'<h[12][^>]*>(.*?)<\/h[12]>', html, re.IGNORECASE)).lower()
        
        brand_mismatch = False
        mismatched_brand = None
        brands = ['paypal', 'netflix', 'microsoft', 'google', 'facebook', 'apple', 'amazon', 'chase', 'bankofamerica', 'wellsfargo']
        
        for brand in brands:
            # Check if brand is mentioned in the main headers or page title
            if brand in page_title or brand in headings_text:
                if brand not in domain.lower():
                    brand_mismatch = True
                    mismatched_brand = brand.capitalize()
                    break
                    
        return {
            "status": "live",
            "has_password": has_password,
            "brand_mismatch": brand_mismatch,
            "mismatched_brand": mismatched_brand
        }
    except Exception:
        return {
            "status": "offline",
            "has_password": False,
            "brand_mismatch": False,
            "mismatched_brand": None
        }

# ✅ Calculate edit distance between two strings (Levenshtein Distance)
def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

# ✅ Check if domain is a typosquatting or brand impersonation attempt
def check_typosquatting(domain):
    domain_lower = domain.lower().strip()
    
    brand_domains = {
        'nios': 'nios.ac.in',
        'paypal': 'paypal.com',
        'netflix': 'netflix.com',
        'microsoft': 'microsoft.com',
        'google': 'google.com',
        'facebook': 'facebook.com',
        'apple': 'apple.com',
        'amazon': 'amazon.com',
        'chase': 'chase.com',
        'bankofamerica': 'bankofamerica.com',
        'wellsfargo': 'wellsfargo.com',
        'youtube': 'youtube.com',
        'linkedin': 'linkedin.com',
        'twitter': 'twitter.com',
        'instagram': 'instagram.com',
        'steam': 'steampowered.com',
        'binance': 'binance.com',
        'coinbase': 'coinbase.com',
        'meta': 'meta.com'
    }
    
    # 1. Brand Impersonation Check (substring match within non-official domains)
    for brand, official in brand_domains.items():
        if brand in domain_lower:
            # Check if this is not the official domain or subdomains of it
            if domain_lower != official and not domain_lower.endswith('.' + official):
                # Ensure the brand segment is a standalone token or part of a hyphenated segment (e.g., old-nios-ac.in)
                # to prevent false positives like 'slipstream.com' for 'steam'
                parts = re.split(r'[^a-zA-Z0-9]', domain_lower)
                if brand in parts or (len(brand) >= 5 and any(brand in p for p in parts)):
                    return True, brand.capitalize(), "impersonation"
                    
    # 2. Typosquatting Check (Levenshtein distance on the primary domain name part)
    domain_part = domain_lower.split('.')[0]
    for brand in brand_domains.keys():
        if domain_part == brand:
            return False, None, None
            
        dist = levenshtein_distance(domain_part, brand)
        if dist in [1, 2]:
            return True, brand.capitalize(), "typosquatting"
            
    return False, None, None


# ✅ Retrieve server IP and physical geolocation details using keyless API
def get_server_geolocation(domain):
    import requests
    try:
        ip = socket.gethostbyname(domain)
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=2.0).json()
        if res.get("status") == "success":
            return {
                "ip": ip,
                "country": res.get("country"),
                "country_code": res.get("countryCode"),
                "city": res.get("city"),
                "isp": res.get("isp")
            }
        return {"ip": ip, "country": "Unknown", "country_code": "N/A", "city": "Unknown", "isp": "Unknown"}
    except Exception:
        return {"ip": "Unknown", "country": "Unknown", "country_code": "N/A", "city": "Unknown", "isp": "Unknown"}

app = Flask(__name__)

# ✅ Absolute path to model
base_dir = os.path.dirname(os.path.abspath(__file__))
model_path = os.path.join(base_dir, "model", "phishing_model.pkl")

model = None
model_error = None
try:
    if os.path.exists(model_path):
        model = joblib.load(model_path)
    else:
        # Fallback to root directory if model is there
        root_model_path = os.path.join(base_dir, "phishing_model.pkl")
        if os.path.exists(root_model_path):
            model = joblib.load(root_model_path)
        else:
            model_error = "Model file 'phishing_model.pkl' not found in model/ or root folder. Please run train_model.py first."
except Exception as e:
    model_error = f"Error loading model: {str(e)}"

# ✅ Feature labels for the graph
labels = ['URL Length', '@ Symbol', 'Subdomains', 'HTTPS', 'Suspicious Word']

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    prediction = None
    plot_div = None
    feature_reports = []
    submitted_url = ""
    risk_score = 0

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()
        if submitted_url:
            # Determine explicit HTTP/HTTPS state of the original URL
            has_http_protocol = submitted_url.lower().startswith("http://")
            has_https_protocol = submitted_url.lower().startswith("https://")
            
            # Format the URL for feature extraction by stripping the protocol prefix if present,
            # to ensure the model doesn't falsely flag standard domains due to protocol leakage.
            clean_url = submitted_url
            if has_https_protocol:
                clean_url = submitted_url[8:]
            elif has_http_protocol:
                clean_url = submitted_url[7:]
            
            # Extract features from clean URL
            features = extract_features(clean_url)
            
            # Override HTTPS feature (index 3) to reflect actual HTTPS presence in user input.
            # If explicitly HTTP, set to 0. If HTTPS or no protocol specified (which browsers default 
            # to secure/standard benign), set to 1.
            features[3] = 1 if has_https_protocol or (not has_http_protocol) else 0

            # Predict using ML model
            ml_pred = 0
            if model:
                try:
                    ml_pred = int(model.predict([features])[0])
                except Exception as e:
                    ml_pred = 0

            # Define domain_name first as it is required by helper functions
            domain_name = clean_url.split('/')[0].split(':')[0]

            # ✅ Run all network-bound queries in parallel using ThreadPoolExecutor to prevent sequential hanging
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=3) as executor:
                future_whois = executor.submit(get_domain_age, submitted_url)
                future_scan = executor.submit(scan_page_content, submitted_url, domain_name)
                future_geo = executor.submit(get_server_geolocation, domain_name)
                
                # Fetch results concurrently
                age_days, whois_status = future_whois.result()
                scan_results = future_scan.result()
                geo_info = future_geo.result()

            # Calculate WHOIS risk and descriptions
            whois_risk = 0
            if whois_status == "unregistered":
                whois_risk = 55
                badge_val = "Not Registered"
                val_text = "Inactive / Unregistered"
                status_val = "suspicious"
                desc_text = "The domain is not registered. This indicates a spoofed, inactive, or highly suspicious URL."
            elif isinstance(age_days, int):
                val_text = f"{age_days} days"
                if age_days < 180:
                    whois_risk = 30
                    badge_val = "Very New Domain"
                    status_val = "suspicious"
                    desc_text = f"Registered very recently ({age_days} days ago). Brand new domains are heavily utilized in immediate phishing scams."
                elif age_days < 365:
                    whois_risk = 15
                    badge_val = "New Domain"
                    status_val = "suspicious"
                    desc_text = f"New domain registered under 1 year ago ({age_days} days ago). Frequently associated with temporary campaigns."
                else:
                    whois_risk = 0
                    badge_val = "Established"
                    status_val = "safe"
                    desc_text = f"Established domain registered over 1 year ago ({age_days} days ago, created {whois_status}). Much higher baseline trust."
            else:
                # unknown or timeout
                whois_risk = 10
                badge_val = "Unknown Age"
                status_val = "safe"
                val_text = "N/A"
                desc_text = "Could not retrieve registration age details via WHOIS (lookup timeout or unsupported TLD)."

            # Perform live page content scanning
            content_risk = 0
            if scan_results["status"] == "live":
                if scan_results["brand_mismatch"]:
                    content_risk = 45
                    content_val = "Brand Mismatch"
                    content_badge = "Brand Spoofing"
                    content_status = "suspicious"
                    content_desc = f"Critical: The page text contains references to '{scan_results['mismatched_brand']}', but the domain is not associated with it."
                elif scan_results["has_password"]:
                    content_risk = 30
                    content_val = "Credentials Requested"
                    content_badge = "Input Warning"
                    content_status = "suspicious"
                    content_desc = "Warning: The page contains password fields or forms requesting credentials. Verify domain legitimacy."
                else:
                    content_risk = 0
                    content_val = "Live & Clean"
                    content_badge = "Active"
                    content_status = "safe"
                    content_desc = "The website is live and does not contain deceptive login forms or brand name mismatches."
            else:
                content_risk = 5 # Small baseline warning for offline pages
                content_val = "Unreachable"
                content_badge = "Offline"
                content_status = "safe"
                content_desc = "The website is currently unreachable or offline. It might be a deactivated or temporary phishing link."

            # Check brand typosquatting similarity
            is_typosquatted, target_brand, check_type = check_typosquatting(domain_name)
            typosquatting_risk = 0
            if is_typosquatted:
                if check_type == "impersonation":
                    typosquatting_risk = 45
                    typo_val = f"Impersonates {target_brand}"
                    typo_badge = "Impersonation Alert"
                    typo_status = "suspicious"
                    typo_desc = f"Brand impersonation detected. The domain '{domain_name}' uses the brand name '{target_brand}' illegally."
                else:
                    typosquatting_risk = 40
                    typo_val = f"Mimics {target_brand}"
                    typo_badge = "Typosquatting Alert"
                    typo_status = "suspicious"
                    typo_desc = f"Visual spoofing detected. The domain '{domain_name}' is highly similar to the brand '{target_brand}', indicating a typosquatting scam."
            else:
                typo_val = "Clean"
                typo_badge = "No Spoofing"
                typo_status = "safe"
                typo_desc = "The domain name does not show deceptive visual similarity to any major target brand."

            # Fetch IP address and geographical server hosting details
            geo_val = f"{geo_info['city']}, {geo_info['country_code']}" if geo_info['country_code'] != 'N/A' else "Unknown"
            geo_badge = geo_info['isp'] if geo_info['isp'] != 'Unknown' else "Offline"
            geo_status = "safe"
            geo_desc = f"Server IP resolved: {geo_info['ip']}. Hosted by {geo_info['isp']} in {geo_info['city']}, {geo_info['country']}."

            # Calculate heuristic risk score
            features_risk = 0
            
            # Feature risks
            if features[0] > 75: # Length
                features_risk += 15
            if features[1] == 1: # @ symbol
                features_risk += 35
            if features[2] == 1: # Too many subdomains
                features_risk += 25
            if features[3] == 0: # Explicit HTTP
                features_risk += 20
            if features[4] == 1: # Suspicious keywords
                features_risk += 25
                
            # Add WHOIS, content, and typosquatting risks
            features_risk += whois_risk
            features_risk += content_risk
            features_risk += typosquatting_risk
            
            # Boost based on ML prediction and WHOIS/Content/Typosquatting status
            risk_score = features_risk
            if ml_pred == 1:
                risk_score = max(risk_score, 50)
                
            # Apply specific boosts for registration/spoofing/typosquatting status
            if whois_status == "unregistered":
                risk_score = max(risk_score, 85)
            elif scan_results["brand_mismatch"]:
                risk_score = max(risk_score, 80) # Brand spoofing is almost certainly phishing
            elif is_typosquatted:
                if check_type == "impersonation":
                    risk_score = max(risk_score, 80) # Brand impersonation is highly suspicious
                else:
                    risk_score = max(risk_score, 75) # High threat if flagged for typosquatting
            elif isinstance(age_days, int) and age_days < 365:
                if ml_pred == 1:
                    risk_score = max(risk_score, 65)
                else:
                    risk_score = max(risk_score, 35)
                
            # Adjust risk score based on general rules (low risk override)
            if features[1] == 0 and features[2] == 0 and features[4] == 0 and features[0] < 50:
                # Capping only applies if the domain is established, not brand-spoofed, and not typosquatted
                if whois_status not in ["unregistered", "invalid"] and (not isinstance(age_days, int) or age_days > 365):
                    if not scan_results["brand_mismatch"] and not is_typosquatted:
                        risk_score = min(risk_score, 15)

            risk_score = min(risk_score, 100)
            
            # Final classification based on Risk Score
            prediction = 1 if risk_score >= 50 else 0
            result = "⚠️ Phishing Site" if prediction == 1 else "🔒 Legitimate Site"

            # Detailed features report for high-end UI rendering
            # 1. URL Length
            length = features[0]
            feature_reports.append({
                "label": "URL Length",
                "value": f"{length} chars",
                "status": "safe" if length <= 75 else "suspicious",
                "description": "Standard URL length, reducing the likelihood of hidden redirects." if length <= 75 else "Very long URL, often used to hide malicious domains or parameters.",
                "badge": "Normal" if length <= 75 else "Long URL"
            })

            # 2. @ Symbol
            has_at = features[1]
            feature_reports.append({
                "label": "@ Symbol Presence",
                "value": "Present" if has_at else "None",
                "status": "suspicious" if has_at else "safe",
                "description": "Using an '@' symbol in a URL ignores everything before it—a classic phishing exploit." if has_at else "No '@' symbol found. Browser resolves domain directly.",
                "badge": "Risky" if has_at else "Safe"
            })

            # 3. Subdomains Count
            has_many_subdomains = features[2]
            dots_count = clean_url.count('.')
            feature_reports.append({
                "label": "Subdomain Structure",
                "value": f"{dots_count} dots",
                "status": "suspicious" if has_many_subdomains else "safe",
                "description": "Multiple subdomains detected, potentially cloaking the destination domain." if has_many_subdomains else "Standard subdomain nesting. No domain cloaking detected.",
                "badge": "Multi-Subdomain" if has_many_subdomains else "Standard"
            })

            # 4. HTTPS Usage
            uses_https = features[3]
            feature_reports.append({
                "label": "SSL/TLS Encryption",
                "value": "HTTPS" if uses_https else "HTTP",
                "status": "safe" if uses_https else "suspicious",
                "description": "Secure HTTPS connection encrypting browser-to-site communication." if uses_https else "Unencrypted HTTP connection. User details are vulnerable to sniffing.",
                "badge": "Encrypted" if uses_https else "Insecure"
            })

            # 5. Suspicious Keywords
            has_keywords = features[4]
            found_keywords = [k for k in ['secure', 'login', 'signin', 'bank', 'update'] if k in clean_url.lower()]
            feature_reports.append({
                "label": "Suspicious Keywords",
                "value": ", ".join(found_keywords) if has_keywords else "None",
                "status": "suspicious" if has_keywords else "safe",
                "description": f"Found warning keyword(s) {found_keywords} used to deceive users into trust." if has_keywords else "No typical deceptive keywords found in URL.",
                "badge": "Keyword Alert" if has_keywords else "Clean"
            })

            # 6. Domain Registration Age (WHOIS)
            feature_reports.append({
                "label": "Domain Registration Age",
                "value": val_text,
                "status": status_val,
                "description": desc_text,
                "badge": badge_val
            })

            # 7. Live Page Content Scan
            feature_reports.append({
                "label": "Live Page Content Scan",
                "value": content_val,
                "status": content_status,
                "description": content_desc,
                "badge": content_badge
            })

            # 8. Brand Typosquatting Check
            feature_reports.append({
                "label": "Brand Typosquatting Check",
                "value": typo_val,
                "status": typo_status,
                "description": typo_desc,
                "badge": typo_badge
            })

            # 9. Server Geolocation & Provider
            feature_reports.append({
                "label": "Server Geolocation",
                "value": geo_val,
                "status": geo_status,
                "description": geo_desc,
                "badge": geo_badge
            })

            # ✅ Create styled bar graph matching glassmorphic dark theme
            bar_color = []
            for i, val in enumerate(features):
                if i == 0:
                    bar_color.append('#6366f1' if val <= 75 else '#ef4444')
                elif i == 3:
                    bar_color.append('#10b981' if val == 1 else '#ef4444')
                else:
                    bar_color.append('#ef4444' if val == 1 else '#10b981')

            fig = go.Figure([go.Bar(
                x=labels,
                y=features,
                marker_color=bar_color,
                marker_line_color='rgba(255,255,255,0.1)',
                marker_line_width=1.5,
                opacity=0.85
            )])
            
            fig.update_layout(
                title={
                    'text': "Extracted URL Features",
                    'y': 0.95,
                    'x': 0.5,
                    'xanchor': 'center',
                    'yanchor': 'top',
                    'font': {'size': 18, 'weight': 'bold', 'color': '#ffffff'}
                },
                font=dict(
                    family="Inter, system-ui, -apple-system, sans-serif",
                    size=12,
                    color="#f8fafc"
                ),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                margin=dict(l=40, r=40, t=60, b=40),
                xaxis=dict(
                    gridcolor="rgba(255,255,255,0.05)",
                    zerolinecolor="rgba(255,255,255,0.1)"
                ),
                yaxis=dict(
                    gridcolor="rgba(255,255,255,0.05)",
                    zerolinecolor="rgba(255,255,255,0.1)"
                ),
                height=420
            )
            plot_div = pio.to_html(fig, full_html=False, config={'displayModeBar': False})

    return render_template(
        "index.html",
        result=result,
        prediction=prediction,
        plot_div=plot_div,
        feature_reports=feature_reports,
        url=submitted_url,
        model_error=model_error,
        risk_score=risk_score
    )

if __name__ == "__main__":
    app.run(debug=True)
