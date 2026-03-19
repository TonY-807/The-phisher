import re
import socket
import datetime
from urllib.parse import urlparse
import requests
from bs4 import BeautifulSoup
import whois

SUSPICIOUS_KEYWORDS = ['login', 'verify', 'bank', 'update', 'secure', 'account', 'auth', 'confirm', 'signin']

def is_https(url):
    return urlparse(url).scheme.lower() == 'https'

def has_suspicious_keywords(url):
    url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in url_lower]
    return found_keywords

def is_ip_address(url):
    domain = urlparse(url).netloc.split(':')[0]
    
    # Try parsing as IPv4
    try:
        socket.inet_aton(domain)
        return True
    except socket.error:
        pass
        
    # Try parsing as IPv6
    try:
        socket.inet_pton(socket.AF_INET6, domain)
        return True
    except socket.error:
        pass
        
    return False

def check_url_length(url):
    return len(url)

def check_domain_age(url):
    try:
        domain = urlparse(url).netloc
        if not domain:
            return None
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if type(creation_date) is list:
            creation_date = creation_date[0]
            
        if creation_date:
            if isinstance(creation_date, str):
                # Unlikely but possible depending on whois response
                creation_date = datetime.datetime.strptime(creation_date, "%Y-%m-%d %H:%M:%S")
            elif hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
                
            age = (datetime.datetime.now() - creation_date).days
            return age
    except Exception:
        return None
    return None

def analyze_html(url):
    results = {'forms_without_action': False, 'external_scripts': 0, 'failed': False}
    try:
        # Added User-Agent to avoid simple bot blocking
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(url, timeout=5, headers=headers)
        soup = BeautifulSoup(response.content, 'html.parser')

        # Check for forms without action or action="#"
        forms = soup.find_all('form')
        for form in forms:
            action = form.get('action')
            if not action or action == '#' or action.startswith('javascript:'):
                results['forms_without_action'] = True
                break

        # Check for external scripts
        domain = urlparse(url).netloc
        scripts = soup.find_all('script')
        for script in scripts:
            src = script.get('src')
            if src:
                script_domain = urlparse(src).netloc
                if script_domain and script_domain != domain:
                    results['external_scripts'] += 1

    except Exception:
        results['failed'] = True
    return results

def check_blacklist(url):
    # Free implementation, could be expanded.
    # Currently safely returning False to demonstrate behavior without external API key limits
    return False

def calculate_risk_score(url):
    # Ensure URL has a scheme
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url

    score = 0
    details = []

    https = is_https(url)
    details.append({"check": "HTTPS Used", "result": "Yes" if https else "No", "safe": https})
    if not https:
        score += 20

    keywords = has_suspicious_keywords(url)
    details.append({"check": "Suspicious Keywords", "result": ", ".join(keywords) if keywords else "None", "safe": len(keywords) == 0})
    if keywords:
        score += 15 * len(keywords)

    is_ip = is_ip_address(url)
    details.append({"check": "Uses IP Address For Domain", "result": "Yes" if is_ip else "No", "safe": not is_ip})
    if is_ip:
        score += 30

    length = check_url_length(url)
    details.append({"check": "URL Length", "result": str(length), "safe": length < 75})
    if length > 75:
        score += 10

    domain_age = check_domain_age(url)
    if domain_age is not None:
        details.append({"check": "Domain Age", "result": f"{domain_age} days", "safe": domain_age > 180})
        if domain_age < 30:
            score += 25
        elif domain_age < 180:
            score += 10
    else:
        details.append({"check": "Domain Age", "result": "Unknown (WHOIS Failed)", "safe": False})
        score += 15

    html_analysis = analyze_html(url)
    if html_analysis['failed']:
         details.append({"check": "HTML Analysis", "result": "Failed to fetch page", "safe": False})
         score += 10 
    else:
         details.append({"check": "Forms without action", "result": "Yes" if html_analysis['forms_without_action'] else "No", "safe": not html_analysis['forms_without_action']})
         if html_analysis['forms_without_action']:
             score += 20

         details.append({"check": "External Scripts", "result": str(html_analysis['external_scripts']), "safe": html_analysis['external_scripts'] < 5})
         if html_analysis['external_scripts'] > 5:
             score += 10
        
    blacklist = check_blacklist(url)
    details.append({"check": "Blacklist Check", "result": "Listed" if blacklist else "Not Listed", "safe": not blacklist})
    if blacklist:
        score += 50

    if score >= 60:
        classification = "Phishing"
    elif score >= 30:
        classification = "Suspicious"
    else:
        classification = "Safe"

    return {
        "url": url,
        "score": min(100, score),
        "classification": classification,
        "details": details
    }
