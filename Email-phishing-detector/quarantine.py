def quarantine_email(mail, email_id):
    mail.create('Quarantine')  # Create 'Quarantine' folder if it doesn't exist
    mail.store(email_id, '+X-GM-LABELS', 'Quarantine')  # Moves the email (Gmail-specific)
    print(f"Email {email_id} moved to Quarantine.")


def build_alert_message(email_info, result, Thresshold):
    """Format a readable alert email body."""
    lines = [
        f"Phishing threat detected — score {result['total_score']} "
        f"(threshold: {Thresshold})",
        "",
        f"From    : {email_info['from']}",
        f"Subject : {email_info['subject']}",
        "",
        "Issues found:",
    ]
    for flag in result['flags']:
        lines.append(f"  • {flag}")
    lines += [
        "",
        f"SPF result  : {result['spf']}",
        f"DKIM result : {result['dkim']}",
        f"VirusTotal  : {'malicious URL found' if result['vt_hit'] else 'clean'}",
        "",
        "The email has been moved to the Quarantine folder.",
    ]
    return "\n".join(lines)
