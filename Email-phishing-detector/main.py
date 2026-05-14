from email_handler import connect_to_email, fetch_emails
from phishing_detection import check_url_virustotal
from spf_dkim_check import run_spf_dkim_checks
from quarantine import quarantine_email,build_alert_message
from alert import send_alert_email
from logger import log_flagged_email

# ── Thresholds ────────────────────────────────────────────────────────────────
#
#  Combined threat score = SPF/DKIM score  +  VirusTotal score
#
#  SPF/DKIM scoring (from spf_dkim_check.py):
#    DKIM fail    → +3   |  DKIM none (no signature) → +1
#    SPF fail     → +3   |  SPF softfail             → +1
#
#  VirusTotal scoring (added below):
#    Malicious URL found → +5
#
#  QUARANTINE_THRESHOLD : total score at or above this → quarantine + alert
#  Set to 3 to catch any single hard failure, or raise to 5 to require more
#  evidence before quarantining.
#
QUARANTINE_THRESHOLD = 3


def score_email(email_info):
    """
    Run all checks, combine scores, and return a result dict:
      {
        'total_score': int,
        'flags':       [str, ...],
        'spf':         str,
        'dkim':        str,
        'vt_hit':      bool,
      }
    """
    # 1. SPF + DKIM
    header_check = run_spf_dkim_checks(email_info)
    total_score  = header_check['score']
    flags        = list(header_check['flags'])

    # 2. VirusTotal URL scan
    vt_hit = check_url_virustotal(email_info['body'])
    if vt_hit:
        total_score += 5
        flags.append("Malicious URL detected by VirusTotal")

    return {
        'total_score': total_score,
        'flags':       flags,
        'spf':         header_check['spf'],
        'dkim':        header_check['dkim'],
        'vt_hit':      vt_hit,
    }



def run():
    mail   = connect_to_email()
    
    # Fetch unread emails
    emails = fetch_emails(mail)  

    if not emails:
        print("No unread emails found.")
        return

    for email_info in emails:
        print(f"\n{'─'*50}")
        print(f"From    : {email_info['from']}")
        print(f"Subject : {email_info['subject']}")

        result = score_email(email_info)

        print(f"Score   : {result['total_score']}  |  "
              f"SPF: {result['spf']}  |  DKIM: {result['dkim']}")

        if result['total_score'] >= QUARANTINE_THRESHOLD:
            print(f"🚨 THREAT — quarantining email (score {result['total_score']})")
            quarantine_email(mail, email_info['id'])
            send_alert_email(
                subject=f"Phishing Alert — score {result['total_score']}",
                message= build_alert_message(email_info, result, QUARANTINE_THRESHOLD),
            )
            log_flagged_email(email_info)
        else:
            print(f"✅ Clean (score {result['total_score']})")


if __name__ == "__main__":
    run()