"""Suffixes of takeover-prone services.

A CNAME to one of these is a *candidate* for subdomain takeover (a DNS record still pointing at a
de-provisioned cloud/SaaS resource). Matching a suffix means "worth verifying", not "vulnerable" –
confirmation needs an authorized active check. See the community "can-i-take-over-xyz" catalog for the
full picture; this is a short list of common suffixes.
"""

from __future__ import annotations

# provider label -> DNS suffixes commonly associated with takeover risk
TAKEOVER_FINGERPRINTS: dict[str, tuple[str, ...]] = {
    "github_pages": ("github.io",),
    "heroku": ("herokuapp.com", "herokudns.com"),
    "aws_s3": ("s3.amazonaws.com", "s3-website.amazonaws.com"),
    "aws_elasticbeanstalk": ("elasticbeanstalk.com",),
    "azure": (
        "azurewebsites.net",
        "cloudapp.net",
        "cloudapp.azure.com",
        "trafficmanager.net",
        "blob.core.windows.net",
    ),
    "fastly": ("fastly.net",),
    "pantheon": ("pantheonsite.io",),
    "ghost": ("ghost.io",),
    "shopify": ("myshopify.com",),
    "surge": ("surge.sh",),
    "tumblr": ("domains.tumblr.com",),
    "unbounce": ("unbouncepages.com",),
    "wordpress": ("wordpress.com",),
    "zendesk": ("zendesk.com",),
    "readthedocs": ("readthedocs.io",),
    "netlify": ("netlify.app", "netlify.com"),
}


def match_fingerprint(hostname: str) -> str | None:
    """Return the provider label if ``hostname`` ends with a known takeover-prone suffix, else None."""
    host = hostname.strip().rstrip(".").lower()
    for provider, suffixes in TAKEOVER_FINGERPRINTS.items():
        for suffix in suffixes:
            if host == suffix or host.endswith("." + suffix):
                return provider
    return None
