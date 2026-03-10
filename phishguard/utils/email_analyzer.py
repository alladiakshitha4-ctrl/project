import re

PHISHING_EMAIL_KEYWORDS = [
    'urgent', 'immediately', 'verify your account', 'click here', 'confirm your',
    'update your information', 'your account has been', 'suspended', 'limited',
    'unusual activity', 'unauthorized', 'security alert', 'password expired',
    'reset your password', 'confirm identity', 'one-time password', 'otp',
    'credit card', 'bank account', 'social security', 'tax refund', 'prize',
    'you have won', 'claim your', 'free gift', 'million dollars', 'inheritance',
    'nigerian', 'wire transfer', 'western union', 'bitcoin', 'crypto',
    'act now', 'limited time', 'expires', 'do not ignore', 'final notice',
    'account closure', 'legal action', 'irs', 'fbi', 'government',
]

SUSPICIOUS_DOMAINS = [
    'xyz', 'top', 'click', 'online', 'live', 'site', 'club',
    'info', 'ml', 'ga', 'gq', 'cf', 'tk', 'pw', 'buzz', 'work'
]

LEGITIMATE_DOMAINS = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com',
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com'
]

class EmailAnalyzer:
    def analyze(self, subject, body, sender):
        flags = []
        score = 0
        full_text = (subject + ' ' + body + ' ' + sender).lower()

        # Check keywords
        matched_keywords = [kw for kw in PHISHING_EMAIL_KEYWORDS if kw in full_text]
        if matched_keywords:
            score += min(len(matched_keywords) * 7, 40)
            flags.append(f'🚨 Phishing keywords detected: {", ".join(matched_keywords[:6])}')

        # Check sender domain
        sender_match = re.search(r'@([\w.-]+)', sender)
        if sender_match:
            sender_domain = sender_match.group(1).lower()
            tld = sender_domain.split('.')[-1]
            if tld in SUSPICIOUS_DOMAINS:
                score += 20
                flags.append(f'⚠️ Suspicious sender domain: {sender_domain}')
            if any(brand in sender_domain for brand in ['paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook']):
                if sender_domain not in LEGITIMATE_DOMAINS:
                    score += 25
                    flags.append(f'🚨 Sender spoofing a known brand: {sender_domain}')
        else:
            score += 10
            flags.append('⚠️ No valid sender email detected')

        # Check URLs in body
        urls = re.findall(r'https?://[^\s<>"]+', body)
        for url in urls:
            if any(s in url for s in ['.xyz', '.top', '.click', '.online', '.tk']):
                score += 15
                flags.append(f'⚠️ Suspicious URL in email: {url[:60]}...')
                break

        # Check urgency language
        urgency_words = ['urgent', 'immediately', 'act now', 'expires', 'final notice', 'do not ignore']
        urgency_found = [w for w in urgency_words if w in full_text]
        if len(urgency_found) >= 2:
            score += 15
            flags.append(f'⚠️ High urgency language detected: {", ".join(urgency_found)}')

        # Generic greeting
        if re.search(r'dear (customer|user|member|client|account holder)', full_text):
            score += 8
            flags.append('⚠️ Generic greeting — legitimate companies use your name')

        # Misspellings (simple check)
        common_misspellings = ['verificaton', 'acccount', 'securty', 'passw0rd', 'confim']
        if any(m in full_text for m in common_misspellings):
            score += 10
            flags.append('⚠️ Spelling errors detected — common in phishing emails')

        # HTML disguised links
        if re.search(r'<a\s+href=["\']https?://[^"\']+["\']', body):
            if len(urls) > 3:
                score += 10
                flags.append('⚠️ Multiple hyperlinks detected in email body')

        score = min(score, 100)

        if score >= 60:
            verdict = 'PHISHING'
        elif score >= 30:
            verdict = 'SUSPICIOUS'
        else:
            verdict = 'SAFE'

        return {
            'risk_score': score,
            'verdict': verdict,
            'flags': flags,
            'keyword_count': len(matched_keywords),
            'url_count': len(urls),
        }
