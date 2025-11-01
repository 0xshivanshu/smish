import requests
import os
from dotenv import load_dotenv

load_dotenv()

vt_api = os.getenv('VIRUSTOTAL_API_KEY')

def scan(url):
    if not vt_api:
        print("Error: VIRUSTOTAL_API_KEY not found in .env file.")
        return {"error": "API key is not configured on the server."}

    params = {'apikey': vt_api, 'resource': url}
    
    try:
        response = requests.get('https://www.virustotal.com/vtapi/v2/url/report', params=params)
        
        # A 204 status code from VirusTotal means the request rate limit was exceeded.
        if response.status_code == 204:
            print("VirusTotal API rate limit exceeded.")
            return {'error': 'Error from VirusTotal API: 204 Rate Limit Exceeded'}
        
        # A 200 status code means the request was successful.
        if response.status_code == 200:
            result = response.json()
            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                total = result.get('total', 0)
                scan_date = result.get('scan_date', 'N/A')
                return {'positives': positives, 'total': total, 'scan_date': scan_date}
            else:
                return {'error': 'No report available for this URL'}
        else:
            return {'error': f'Error from VirusTotal API: {response.status_code}'}

    except requests.exceptions.RequestException as e:
        print(f"Error communicating with VirusTotal: {e}")
        return {"status": "error", "source": "VirusTotal API", "details": "Could not connect to analysis service."}
