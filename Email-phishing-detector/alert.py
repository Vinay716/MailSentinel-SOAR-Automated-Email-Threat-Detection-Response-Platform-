import os
from dotenv import load_dotenv
import smtplib
from email.mime.text import MIMEText


load_dotenv()


def send_alert_email(subject, message):
    alert_email = os.getenv("ALERT_EMAIL")          # Who will receive the alert
    smtp_user = os.getenv("SMTP_USER")              # The email account used to send alerts
    smtp_password = os.getenv("SMTP_PASSWORD")      # App password for SMTP_USER
    smtp_server = os.getenv("SMTP_SERVER", "smtp.gmail.com")
    smtp_port = int(os.getenv("SMTP_PORT", 587))    # Port for TLS (587)

    msg = MIMEText(message)
    msg['Subject'] = subject
    msg['From'] = alert_email
    msg['To'] =  "bussinessguru83@gmail.com"# Replace with security team email

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(alert_email, smtp_password)
        server.sendmail(alert_email,alert_email, msg.as_string())                                                      #Remove the all the things from the double coat and add your alert email
    print("Alert email sent.")


