
import os
from urllib.parse import urlparse
from dotenv import load_dotenv
import requests
import hashlib

from flask import Flask, request, jsonify

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Import all our custom modules
import crypto_utils 
import nmapScanner
import zapScanner
import sandboxScanner
import virustotalScanner

load_dotenv()
app = Flask(__name__)

client_public_keys = {}

print("Generating client's RSA key pair for secure sessions...")
server_key = RSA.generate(2048)
SERVER_PRIVATE_KEY_PEM = server_key.export_key().decode('utf-8')
SERVER_PUBLIC_KEY_PEM = server_key.publickey().export_key().decode('utf-8')
print("Client key pair generated. \n Public Key: ", SERVER_PUBLIC_KEY_PEM[27:52] ,"... \nPrivate Key: ", SERVER_PRIVATE_KEY_PEM[32:57] ,"...")

AES_KEY = os.getenv('AES_SECRET_KEY').encode('utf-8')
print("AES Key for symmetric encryption loaded from .env: ", AES_KEY)

def demonstrate_crypto(data_to_process: str):
    """
    Performs and prints the results of hashing and encryption.
    """
    print("\n" + "="*25 + " CRYPTOGRAPHY DEMO " + "="*25)
    hashed_data = crypto_utils.hash_data(data_to_process)
    print(f"Original Data    : {data_to_process}")
    print(f"SHA-256 Hash     : {hashed_data}")
    nonce, ciphertext = crypto_utils.encrypt_data(AES_KEY, data_to_process)
    print(f"AES Encrypted    : (Nonce: {nonce}, Ciphertext: {ciphertext})")
    print("="*70 + "\n")

def resolve_final_url(url):
    """
    Follows all redirects of a given URL and returns the final destination.
    """
    try:
        response = requests.head(url, allow_redirects=True, timeout=10)
        return response.url
    except requests.exceptions.RequestException as e:
        print(f"Could not resolve redirect for {url}: {e}")
        return url


@app.route('/get_server_public_key', methods=['GET'])
def get_server_public_key():
    return jsonify({'server_public_key': SERVER_PUBLIC_KEY_PEM})

@app.route('/register_client', methods=['POST'])
def register_client():
    data = request.get_json()
    client_id = data.get('client_id')
    public_key = data.get('public_key')
    if not client_id or not public_key:
        return jsonify({'error': 'Client ID and public key are required'}), 400
    
    print(f"Registering new client: {client_id}")
    client_public_keys[client_id] = public_key
    return jsonify({'status': 'Client registered successfully'})

@app.route('/secure_analyze', methods=['POST'])
def secure_analyze():
    data = request.get_json()
    return jsonify({'status': 'Secure endpoint reached (logic to be fully implemented).'})


@app.route('/analyze/network', methods=['POST'])
def analyze_network():
    data = request.get_json()
    url = data.get('url')
    if not url: return jsonify({'error': 'URL required'}), 400
    
    demonstrate_crypto(url)
    
    domain = urlparse(url).netloc
    findings = nmapScanner.scan(domain)
    score = 5 if findings else 0
    
    return jsonify({
        'scanner': 'Nmap Vulnerability Scan',
        'score': score,
        'findings': findings if findings else ["No critical network vulnerabilities found."]
    })

@app.route('/analyze/reputation', methods=['POST'])
def analyze_reputation():
    data = request.get_json()
    url = data.get('url')
    if not url: return jsonify({'error': 'URL required'}), 400

    demonstrate_crypto(url)

    result = virustotalScanner.scan(url)
    score = 0
    findings = []
    if 'error' not in result:
        positives = result.get('positives', 0)
        total = result.get('total', 0)
        findings.append(f"{positives}/{total} vendors flagged this URL.")
        if positives > 4: score = 100
        elif positives > 0: score = 30
    else:
        findings.append(result['error'])
        
    return jsonify({
        'scanner': 'VirusTotal API',
        'score': score,
        'findings': findings
    })

@app.route('/analyze/behavioral', methods=['POST'])
def analyze_behavioral():
    data = request.get_json()
    url = data.get('url')
    if not url: return jsonify({'error': 'URL required'}), 400

    demonstrate_crypto(url)

    sandbox_path = os.getenv('SANDBOX_DOWNLOAD_PATH')
    if not sandbox_path or not os.path.isdir(sandbox_path):
        return jsonify({'scanner': 'Sandbox Simulation', 'score': 100, 'findings': ["Sandbox path is not configured correctly in the .env file or does not exist."]})

    final_url = resolve_final_url(url)
    findings = sandboxScanner.scan(final_url, sandbox_path)
    score = 100 if findings[0] != 'No malicious behavior (like drive-by downloads) detected.' else 0
    print(f"Sandbox findings: {findings}")
    return jsonify({
        'scanner': 'Sandbox Simulation',
        'score': score,
        'findings': findings if findings else ["No malicious behavior (like drive-by downloads) detected."]
    })

@app.route('/analyze/application', methods=['POST'])
def analyze_application():
    data = request.get_json()
    url = data.get('url')
    if not url: return jsonify({'error': 'URL required'}), 400

    demonstrate_crypto(url)

    final_url = resolve_final_url(url)
    findings = zapScanner.scan(final_url)
    if len(findings) > 50:
        score = 100
    elif len(findings) > 0:
        score = len(findings) * 2
    else:  
        score = 0

    return jsonify({
        'scanner': 'OWASP ZAP Scan',
        'score': score,
        'findings': findings if findings else ["No high-risk web application vulnerabilities found."]
    })


#  APP LAUNCHER
if __name__ == '__main__':
    print("Starting Flask server...")
    app.run(host='0.0.0.0', port=5000)