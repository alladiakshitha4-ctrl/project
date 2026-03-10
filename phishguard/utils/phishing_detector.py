import re
import math
import json
import os
import pickle
import numpy as np
from datetime import datetime
from urllib.parse import urlparse

# ── Suspicious keyword lists ───────────────────────────────────────────────────
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'confirm', 'secure', 'account',
    'banking', 'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook',
    'password', 'credential', 'wallet', 'suspended', 'urgent', 'verify-now',
    'click-here', 'free', 'winner', 'prize', 'claim', 'reward', 'limited',
    'expire', 'immediate', 'alert', 'warning', 'blocked', 'support', 'helpdesk',
    'webscr', 'ebayisapi', 'signin', 'bank', 'credit', 'debit', 'card',
    'ssn', 'social-security', 'irs', 'tax-refund', 'cryptocurrency', 'bitcoin'
]

LEGITIMATE_TLDS = {'.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.uk', '.us'}

SUSPICIOUS_TLDS = {'.xyz', '.top', '.click', '.club', '.online', '.site', '.live',
                   '.info', '.pw', '.ml', '.ga', '.gq', '.cf', '.tk', '.buzz',
                   '.work', '.link', '.men', '.loan', '.download', '.racing'}

KNOWN_BRANDS = [
    'paypal', 'amazon', 'apple', 'microsoft', 'google', 'facebook', 'netflix',
    'instagram', 'twitter', 'linkedin', 'youtube', 'github', 'dropbox',
    'spotify', 'adobe', 'ebay', 'walmart', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'coinbase', 'binance'
]


class PhishingDetector:
    def __init__(self):
        self.model = None
        self.model_accuracy = 0.967
        self._load_or_train_model()

    def _load_or_train_model(self):
        model_path = os.path.join(os.path.dirname(__file__), '..', 'models', 'phish_model.pkl')
        os.makedirs(os.path.dirname(model_path), exist_ok=True)
        if os.path.exists(model_path):
            with open(model_path, 'rb') as f:
                data = pickle.load(f)
                self.model = data['model']
                self.model_accuracy = data.get('accuracy', 0.967)
        else:
            self._train_model(model_path)

    def _train_model(self, save_path):
        from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import accuracy_score
        from sklearn.preprocessing import StandardScaler
        from sklearn.pipeline import Pipeline
        import random, string

        random.seed(42)
        np.random.seed(42)

        # ── Synthetic dataset generation ───────────────────────────────────────
        phishing_urls = [
            'http://paypa1-secure-login.xyz/account/verify',
            'http://amazon-prize-winner.click/claim/reward',
            'http://secure-banking-update.online/login/confirm',
            'http://apple-id-suspended.top/restore',
            'http://microsoft-alert-warning.live/verify-now',
            'http://192.168.1.1/bank/login.php',
            'http://google-account-verify.xyz/security',
            'http://facebook-login-secure.online/auth',
            'http://netflix-billing-update.club/payment',
            'http://ebay-account-suspended.site/restore',
            'http://irs-tax-refund.loan/claim',
            'http://coinbase-wallet-update.xyz/verify',
            'http://chase-secure-login.online/auth',
        ]
        legitimate_urls = [
            'https://www.google.com/search',
            'https://www.amazon.com/products',
            'https://github.com/user/repo',
            'https://stackoverflow.com/questions',
            'https://www.wikipedia.org/wiki/Python',
            'https://news.ycombinator.com',
            'https://www.reddit.com/r/programming',
            'https://docs.python.org/3/library',
            'https://www.youtube.com/watch',
            'https://www.linkedin.com/in/user',
            'https://twitter.com/home',
            'https://www.apple.com/store',
        ]

        all_urls, labels = [], []
        for url in phishing_urls:
            all_urls.append(url)
            labels.append(1)
            # Augment
            for _ in range(8):
                kw = random.choice(PHISHING_KEYWORDS)
                dom = ''.join(random.choices(string.ascii_lowercase, k=random.randint(5, 12)))
                tld = random.choice(list(SUSPICIOUS_TLDS))
                u = f"http://{dom}-{kw}{tld}/{''.join(random.choices(string.ascii_lowercase, k=6))}"
                all_urls.append(u)
                labels.append(1)

        for url in legitimate_urls:
            all_urls.append(url)
            labels.append(0)
            for _ in range(8):
                sub = random.choice(['www', 'docs', 'support', 'blog', 'shop'])
                dom = random.choice(['company', 'service', 'platform', 'tech', 'software'])
                tld = random.choice(list(LEGITIMATE_TLDS))
                path = '/'.join([''.join(random.choices(string.ascii_lowercase, k=random.randint(3, 8))) for _ in range(random.randint(1, 3))])
                u = f"https://{sub}.{dom}{tld}/{path}"
                all_urls.append(u)
                labels.append(0)

        X = np.array([self._extract_features_array(u) for u in all_urls])
        y = np.array(labels)
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

        model = Pipeline([
            ('scaler', StandardScaler()),
            ('clf', GradientBoostingClassifier(n_estimators=200, max_depth=5, random_state=42))
        ])
        model.fit(X_train, y_train)
        self.model_accuracy = round(accuracy_score(y_test, model.predict(X_test)), 4)
        self.model = model

        with open(save_path, 'wb') as f:
            pickle.dump({'model': model, 'accuracy': self.model_accuracy}, f)

    def _extract_features_array(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()

        features = [
            len(url),
            url.count('.'),
            url.count('-'),
            url.count('@'),
            url.count('?'),
            url.count('='),
            url.count('//'),
            url.count('%'),
            int('https' not in url.lower()),
            int(bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))),
            sum(1 for kw in PHISHING_KEYWORDS if kw in full),
            self._entropy(domain),
            len(domain),
            sum(1 for b in KNOWN_BRANDS if b in domain and domain != f'www.{b}.com'),
            int(any(tld in domain for tld in SUSPICIOUS_TLDS)),
            len(path),
            path.count('/'),
            int(bool(re.search(r'\.php|\.asp|\.html', path))),
            url.count('0') + url.count('1'),
            int(len(domain.split('.')) > 4),
        ]
        return features

    def _entropy(self, s):
        if not s:
            return 0
        from collections import Counter
        counts = Counter(s)
        total = len(s)
        return -sum((c / total) * math.log2(c / total) for c in counts.values())

    def analyze(self, url):
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full = url.lower()

        # Feature extraction
        features = {}
        features['url_length'] = len(url)
        features['has_https'] = url.startswith('https://')
        features['has_ip'] = bool(re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url))
        features['suspicious_keywords'] = [kw for kw in PHISHING_KEYWORDS if kw in full]
        features['keyword_count'] = len(features['suspicious_keywords'])
        features['domain_entropy'] = round(self._entropy(domain), 3)
        features['has_suspicious_tld'] = any(tld in domain for tld in SUSPICIOUS_TLDS)
        features['subdomain_count'] = len(domain.split('.')) - 2
        features['has_brand_impersonation'] = any(b in domain for b in KNOWN_BRANDS
                                                   if domain not in [f'www.{b}.com', f'{b}.com'])
        features['special_char_count'] = sum(url.count(c) for c in '@-_?=%')
        features['domain_length'] = len(domain)
        features['path_depth'] = path.count('/')
        features['domain_age_days'] = self._estimate_domain_age(domain)
        features['dot_count'] = url.count('.')
        features['hyphen_count'] = url.count('-')

        # ML prediction
        arr = np.array([self._extract_features_array(url)]).reshape(1, -1)
        if self.model:
            proba = self.model.predict_proba(arr)[0][1]
            ml_score = float(proba) * 100
        else:
            ml_score = 50.0

        # Rule-based scoring
        rule_score = 0
        if not features['has_https']:
            rule_score += 15
        if features['has_ip']:
            rule_score += 30
        if features['keyword_count'] > 0:
            rule_score += min(features['keyword_count'] * 8, 25)
        if features['has_suspicious_tld']:
            rule_score += 20
        if features['has_brand_impersonation']:
            rule_score += 25
        if features['subdomain_count'] > 2:
            rule_score += 10
        if features['domain_entropy'] > 3.5:
            rule_score += 10
        if features['url_length'] > 100:
            rule_score += 10
        if features['hyphen_count'] > 3:
            rule_score += 5
        if features['domain_age_days'] < 30:
            rule_score += 15

        rule_score = min(rule_score, 100)
        final_score = round(0.6 * ml_score + 0.4 * rule_score, 1)

        if final_score >= 65:
            verdict = 'PHISHING'
            verdict_color = 'danger'
        elif final_score >= 35:
            verdict = 'SUSPICIOUS'
            verdict_color = 'warning'
        else:
            verdict = 'SAFE'
            verdict_color = 'success'

        recommendations = self._get_recommendations(features, final_score)

        return {
            'url': url,
            'risk_score': final_score,
            'verdict': verdict,
            'verdict_color': verdict_color,
            'features': features,
            'ml_score': round(ml_score, 1),
            'rule_score': round(rule_score, 1),
            'recommendations': recommendations,
            'model_accuracy': self.model_accuracy
        }

    def _estimate_domain_age(self, domain):
        """Estimate domain age heuristically"""
        if any(d in domain for d in ['google', 'amazon', 'facebook', 'microsoft', 'apple',
                                       'github', 'wikipedia', 'youtube', 'reddit']):
            return 5000
        if any(tld in domain for tld in SUSPICIOUS_TLDS):
            return 15
        if any(kw in domain for kw in PHISHING_KEYWORDS):
            return 20
        return 365

    def _get_recommendations(self, features, score):
        recs = []
        if not features['has_https']:
            recs.append('⚠️ This site does not use HTTPS encryption. Avoid entering sensitive data.')
        if features['has_ip']:
            recs.append('🚨 URL uses an IP address instead of a domain name — highly suspicious.')
        if features['has_brand_impersonation']:
            recs.append('🚨 Domain appears to impersonate a well-known brand. Verify the official website.')
        if features['keyword_count'] > 0:
            recs.append(f'⚠️ Contains phishing keywords: {", ".join(features["suspicious_keywords"][:5])}')
        if features['has_suspicious_tld']:
            recs.append('⚠️ Uses a high-risk top-level domain commonly associated with phishing.')
        if features['subdomain_count'] > 2:
            recs.append('⚠️ Excessive subdomains detected — a common phishing tactic.')
        if score >= 65:
            recs.append('🚨 DO NOT visit this website or enter any personal information.')
        elif score >= 35:
            recs.append('⚠️ Proceed with extreme caution. Verify this site through official channels.')
        else:
            recs.append('✅ This URL appears safe, but always stay vigilant online.')
        return recs

    def get_model_accuracy(self):
        return self.model_accuracy
