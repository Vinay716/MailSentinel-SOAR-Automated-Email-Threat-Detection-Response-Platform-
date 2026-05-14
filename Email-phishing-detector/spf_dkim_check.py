import dns.resolver
import dkim
import re
import socket


# ─────────────────────────────────────────────
#  DKIM CHECK
# ─────────────────────────────────────────────

def check_dkim(raw_bytes):
    """
    Verify the DKIM signature in the raw email bytes.
    Returns: 'pass', 'fail', or 'none' (no signature present)
    """
    try:
        d = dkim.DKIM(raw_bytes)
        result = d.verify()
        if result:
            print("✅ DKIM: pass")
            return "pass"
        else:
            print("❌ DKIM: fail (signature invalid)")
            return "fail"
    except dkim.DKIMException as e:
        print(f"❌ DKIM: fail ({e})")
        return "fail"
    except Exception as e:
        # No DKIM header at all, or DNS lookup failed
        print(f"⚠️  DKIM: none ({e})")
        return "none"


# ─────────────────────────────────────────────
#  SPF CHECK
# ─────────────────────────────────────────────

def _extract_sender_domain(from_header):
    """Pull the domain out of a From header like 'Name <user@domain.com>'."""
    match = re.search(r'@([\w.\-]+)', from_header)
    return match.group(1).lower() if match else None


def _get_spf_record(domain):
    """Fetch the TXT record containing the SPF policy for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = b''.join(rdata.strings).decode('utf-8', errors='ignore')
            if txt.startswith('v=spf1'):
                return txt
    except Exception:
        pass
    return None


def _evaluate_spf(spf_record, sender_ip, domain):
    """
    Minimal SPF evaluator — covers the most common mechanisms:
      ip4, ip6, include, a, mx, ~all, -all, +all
    Returns: 'pass', 'softfail', 'fail', or 'neutral'
    """
    if not spf_record:
        return "neutral"

    import ipaddress

    def ip_matches(cidr, ip):
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    def resolve_a(host):
        try:
            return [r.address for r in dns.resolver.resolve(host, 'A')]
        except Exception:
            return []

    def resolve_mx(host):
        ips = []
        try:
            for mx in dns.resolver.resolve(host, 'MX'):
                ips += resolve_a(str(mx.exchange))
        except Exception:
            pass
        return ips

    terms = spf_record.split()
    for term in terms[1:]:  # skip 'v=spf1'
        qualifier = '+'
        if term[0] in '+-~?':
            qualifier, term = term[0], term[1:]

        def outcome(q):
            return {'+':"pass", '-':"fail", '~':"softfail", '?':"neutral"}[q]

        if term.startswith('ip4:') or term.startswith('ip6:'):
            cidr = term.split(':', 1)[1]
            if ip_matches(cidr, sender_ip):
                return outcome(qualifier)

        elif term.startswith('include:'):
            inc_domain = term.split(':', 1)[1]
            inc_record = _get_spf_record(inc_domain)
            inc_result = _evaluate_spf(inc_record, sender_ip, inc_domain)
            if inc_result == 'pass':
                return outcome(qualifier)

        elif term == 'a' or term.startswith('a:'):
            host = term.split(':', 1)[1] if ':' in term else domain
            if sender_ip in resolve_a(host):
                return outcome(qualifier)

        elif term == 'mx' or term.startswith('mx:'):
            host = term.split(':', 1)[1] if ':' in term else domain
            if sender_ip in resolve_mx(host):
                return outcome(qualifier)

        elif term == 'all':
            return outcome(qualifier)   # catch-all at end of record

    return "neutral"


def check_spf(from_header, sender_ip=None):
    """
    Full SPF check.
      - from_header : the raw From header string
      - sender_ip   : IP of the sending server (optional; falls back to DNS A record)
    Returns: 'pass', 'softfail', 'fail', or 'neutral'
    """
    domain = _extract_sender_domain(from_header)
    if not domain:
        print("⚠️  SPF: neutral (could not parse sender domain)")
        return "neutral"

    # If no IP provided, resolve the domain's A record as a best-effort check
    if not sender_ip:
        try:
            sender_ip = socket.gethostbyname(domain)
        except socket.gaierror:
            print(f"⚠️  SPF: neutral (DNS resolution failed for {domain})")
            return "neutral"

    spf_record = _get_spf_record(domain)
    if not spf_record:
        print(f"⚠️  SPF: neutral (no SPF record for {domain})")
        return "neutral"

    result = _evaluate_spf(spf_record, sender_ip, domain)
    icon = "✅" if result == "pass" else ("⚠️ " if result == "softfail" else "❌")
    print(f"{icon} SPF: {result} (domain: {domain})")
    return result


# ─────────────────────────────────────────────
#  COMBINED RESULT
# ─────────────────────────────────────────────

def run_spf_dkim_checks(email_info):
    """
    Run both checks and return a summary dict:
      {
        'spf':  'pass' | 'softfail' | 'fail' | 'neutral',
        'dkim': 'pass' | 'fail' | 'none',
        'score': int,          # 0 = clean, higher = more suspicious
        'flags': [str, ...]    # human-readable list of issues
      }

    Scoring:
      DKIM fail   → +3
      DKIM none   → +1
      SPF fail    → +3
      SPF softfail→ +1
    """
    spf_result  = check_spf(email_info['from'], email_info.get('sender_ip'))
    dkim_result = check_dkim(email_info['raw_bytes'])

    score = 0
    flags = []

    if dkim_result == 'fail':
        score += 3
        flags.append("DKIM signature invalid")
    elif dkim_result == 'none':
        score += 1
        flags.append("No DKIM signature")

    if spf_result == 'fail':
        score += 3
        flags.append("SPF hard fail")
    elif spf_result == 'softfail':
        score += 1
        flags.append("SPF soft fail")

    return {
        'spf':   spf_result,
        'dkim':  dkim_result,
        'score': score,
        'flags': flags,
    }