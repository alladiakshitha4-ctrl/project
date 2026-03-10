import re

# Simulated threat intelligence database
KNOWN_PHISHING_DOMAINS = {
    'paypa1.com', 'amazon-prize.xyz', 'secure-banking.online',
    'apple-support.top', 'microsoft-alert.live', 'google-verify.xyz',
    'facebook-secure.online', 'netflix-billing.club', 'ebay-suspended.site',
}

THREAT_FEEDS = {
    'PhishTank': 'https://phishtank.org',
    'OpenPhish': 'https://openphish.com',
    'Google Safe Browsing': 'https://safebrowsing.google.com',
    'URLhaus': 'https://urlhaus.abuse.ch',
    'Cisco Talos': 'https://talosintelligence.com',
}

class ThreatIntelligence:
    def check_url(self, url):
        """Check URL against known threat databases (simulated)"""
        domain = self._extract_domain(url)
        results = {}

        # Simulate feed checks
        is_known = domain in KNOWN_PHISHING_DOMAINS
        for feed_name in THREAT_FEEDS:
            # Simulate: known domains are flagged by all feeds
            if is_known:
                results[feed_name] = {'status': 'MALICIOUS', 'listed': True}
            else:
                # Heuristic: check if domain looks suspicious
                suspicious_score = self._heuristic_check(url)
                if suspicious_score > 0.7:
                    results[feed_name] = {'status': 'SUSPICIOUS', 'listed': False}
                else:
                    results[feed_name] = {'status': 'CLEAN', 'listed': False}

        flagged_count = sum(1 for r in results.values() if r['listed'])
        return {
            'feeds': results,
            'flagged_count': flagged_count,
            'total_feeds': len(THREAT_FEEDS),
            'threat_level': 'HIGH' if flagged_count >= 2 else ('MEDIUM' if flagged_count == 1 else 'LOW'),
            'feed_names': list(THREAT_FEEDS.keys()),
        }

    def _extract_domain(self, url):
        match = re.search(r'(?:https?://)?([^/?\s]+)', url)
        return match.group(1).lower() if match else ''

    def _heuristic_check(self, url):
        score = 0
        suspicious_tlds = ['.xyz', '.top', '.click', '.online', '.tk', '.ml', '.ga']
        phishing_kws = ['login', 'verify', 'secure', 'update', 'confirm', 'suspended']
        if any(t in url for t in suspicious_tlds):
            score += 0.4
        if any(k in url.lower() for k in phishing_kws):
            score += 0.3
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            score += 0.5
        return min(score, 1.0)
