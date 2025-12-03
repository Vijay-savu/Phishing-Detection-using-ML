import json
import tldextract

class RuleMatcher:
    def __init__(self, pattern_file):
        self.trusted = []
        self.untrusted = []
        try:
            with open(pattern_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.trusted = data.get("trusted", [])
                self.untrusted = data.get("untrusted", [])
        except Exception:
            pass

    def match(self, url):
        url = url.lower()
        ext = tldextract.extract(url)
        domain = ext.registered_domain

        # Match trusted whitelist
        for t in self.trusted:
            if t in domain:
                return "trusted", t

        # Match untrusted blacklist
        for u in self.untrusted:
            if u in url:
                return "untrusted", u

        return None, None
