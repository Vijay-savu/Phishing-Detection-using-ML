from rule_matcher import apply_rules

# Test URLs
urls = [
    "https://github.commmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm",
    "https://google.com/login",
    "https://trusted-site.com",
    "https://example.com/very/long/url/that/is/suspicious/and/contains//double/slash",
    "https://normal-site.com"
]

for u in urls:
    result = apply_rules(u)
    print(f"URL: {u}\nVerdict: {result['verdict']}\nReason: {result['reason']}\n")
