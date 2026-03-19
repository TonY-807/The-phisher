import email
from email import policy
from email.parser import BytesParser
import re
import analyzer

EMAIL_SUSPICIOUS_KEYWORDS = ['urgent', 'verify', 'account suspended', 'login', 'action required', 'password', 'bank']
RISKY_ATTACHMENTS = ['.exe', '.zip', '.js', '.vbs', '.scr', '.bat', '.cmd']

def extract_urls(text):
    url_pattern = re.compile(r'(https?://[^\s<>"]+)')
    return url_pattern.findall(text)

def analyze_email_file(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return analyze_email_message(msg)

def analyze_email_text(raw_text):
    msg = email.message_from_string(raw_text, policy=policy.default)
    return analyze_email_message(msg)

def analyze_email_message(msg):
    score = 0
    details = []
    
    sender = str(msg.get('From', ''))
    reply_to = str(msg.get('Reply-To', ''))
    
    details.append({"check": "Sender", "result": sender, "safe": True})
    
    # Check Header Mismatch
    if reply_to and sender:
        if reply_to.lower() not in sender.lower() and sender.lower() not in reply_to.lower():
             details.append({"check": "Header Mismatch", "result": f"Reply-To ({reply_to}) differs from From ({sender})", "safe": False})
             score += 30
        else:
             details.append({"check": "Header Mismatch", "result": "Headers Match", "safe": True})
             
    # Extract body
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode(errors='ignore')
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body = payload.decode(errors='ignore')
        
    # Check keywords
    body_lower = body.lower()
    found_keywords = [kw for kw in EMAIL_SUSPICIOUS_KEYWORDS if kw in body_lower]
    details.append({"check": "Suspicious Keywords", "result": ", ".join(found_keywords) if found_keywords else "None", "safe": len(found_keywords) == 0})
    if found_keywords:
        score += 15 * len(found_keywords)
        
    # Check Attachments
    attachments = []
    has_risky = False
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
            if any(filename.lower().endswith(ext) for ext in RISKY_ATTACHMENTS):
                has_risky = True
                
    if attachments:
        details.append({"check": "Attachments", "result": f"Found {len(attachments)}: {', '.join(attachments)}", "safe": not has_risky})
        if has_risky:
             score += 40
    else:
         details.append({"check": "Attachments", "result": "None", "safe": True})
         
    # Check URLs in email
    urls = extract_urls(body)
    if urls:
        # Deduplicate URLs
        urls = list(set(urls))
        details.append({"check": "Extracted URLs", "result": f"Found {len(urls)} URLs.", "safe": True})
        # Analyze first few URLs
        for url in urls[:3]:
            url_result = analyzer.calculate_risk_score(url)
            if url_result['classification'] == 'Phishing':
                score += 50
                details.append({"check": f"URL Risk for {url[:30]}...", "result": "Phishing URL detected", "safe": False})
            elif url_result['classification'] == 'Suspicious':
                score += 20
                details.append({"check": f"URL Risk for {url[:30]}...", "result": "Suspicious URL detected", "safe": False})
    
    if score >= 60:
        classification = "Phishing"
    elif score >= 30:
        classification = "Suspicious"
    else:
        classification = "Safe"
        
    return {
        "input_data": sender or "Email Input",
        "score": min(100, score),
        "classification": classification,
        "details": details,
        "type": "Email"
    }
