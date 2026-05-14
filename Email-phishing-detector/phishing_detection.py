import requests
import base64
import re 
import os
from dotenv import load_dotenv


load_dotenv()

def check_url_virustotal(email_body):
    api_key = os.getenv("VIRUSTOTAL_API_KEY") #Add your virustotal API key
    urls = re.findall(r'https?://[^\s]+', email_body)  # Extract URLs
    print(urls)

    for url in urls:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)

        if response.status_code == 200:
            result = response.json()
            #print("VirusTotal Analysis Result:", result)  # Print the result for debugging
            print("VirusTotal Done!")
            # Check for malicious indicators
            if result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0) > 0:
                print("Flag For Pyshing")
                return True  # Flagged as phishing


    return False  # No phishing detected

