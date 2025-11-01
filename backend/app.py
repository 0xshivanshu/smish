from flask import Flask, request, jsonify
import virustotalScanner

app = Flask(__name__)

@app.route('/analyze_url', methods=['POST'])
def analyze_url():
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'URL is required in the request body'}), 400
    
    url = data['url']
    
    print(f"Received request to analyze URL: {url}")
    
    result = virustotalScanner.scan(url)
    
    print(f"Scan result: {result}")
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)