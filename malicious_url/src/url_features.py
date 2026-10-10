import re
import ipaddress
from urllib.parse import urlsplit, unquote


def extract_url_features(url: str) -> dict:
    """Extract provisional URL-only features for CyberGuard."""

    if not isinstance(url, str) or not url.strip():
        raise ValueError("Please provide a non-empty URL.")

    url = url.strip()

    # Parse consistently, including URLs without a scheme.
    parse_value = url if "://" in url else "//" + url

    try:
        parsed = urlsplit(parse_value)
        hostname = (parsed.hostname or "").lower()
    except ValueError as exc:
        raise ValueError("Invalid URL format.") from exc

    if not hostname:
        raise ValueError("Could not extract a hostname from the URL.")

    # Strip IPv6 brackets are handled by parsed.hostname.
    try:
        ipaddress.ip_address(hostname)
        is_ip = 1
    except ValueError:
        is_ip = 0

    # Counts are based on the submitted URL, not the decoded version.
    length = len(url)
    letters = sum(c.isalpha() for c in url)
    digits = sum(c.isdigit() for c in url)

    # This is a provisional heuristic, not a confirmed PhiUSIIL formula.
    encoded_matches = re.findall(r"%[0-9a-fA-F]{2}", url)
    has_obfuscation = int(
        bool(encoded_matches)
        or "@" in url
        or re.search(r"0x[0-9a-fA-F]+", url) is not None
    )

    # Remove a trailing dot before counting hostname labels.
    normalized_host = hostname.rstrip(".")
    labels = normalized_host.split(".")

    # Approximate registrable-domain length; not a public-suffix-aware parser.
    domain_length = len(normalized_host)

    # A basic approximation: labels preceding the final two labels.
    subdomain_count = max(0, len(labels) - 2) if not is_ip else 0

    # Count special characters excluding alphanumerics.
    special_chars = sum(not c.isalnum() for c in url)

    # Keep the feature names exactly aligned with the model schema.
    return {
        "URLLength": length,
        "DomainLength": domain_length,
        "IsDomainIP": is_ip,
        "TLDLength": len(labels[-1]) if labels else 0,
        "NoOfSubDomain": subdomain_count,
        "HasObfuscation": has_obfuscation,
        "NoOfObfuscatedChar": len(encoded_matches),
        "ObfuscationRatio": (
            len(encoded_matches) / length if length else 0.0
        ),
        "NoOfLettersInURL": letters,
        "LetterRatioInURL": letters / length if length else 0.0,
        "NoOfDegitsInURL": digits,
        "DegitRatioInURL": digits / length if length else 0.0,
        "NoOfEqualsInURL": url.count("="),
        "NoOfQMarkInURL": url.count("?"),
        "NoOfAmpersandInURL": url.count("&"),
        "NoOfOtherSpecialCharsInURL": special_chars,
        "SpacialCharRatioInURL": (
            special_chars / length if length else 0.0
        ),
        "IsHTTPS": int(url.lower().startswith("https://")),
    }