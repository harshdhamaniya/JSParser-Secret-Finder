from flask import Flask, render_template, request, jsonify, send_file
import requests
import re
from fpdf import FPDF
import os
from werkzeug.exceptions import BadRequest

app = Flask(__name__)

# Patterns for detecting direct API URLs and sensitive information
url_pattern = re.compile(r"[^/][`'\"]([\/][a-zA-Z0-9_.-]+)+(?!([gimuy]*[,;\s])|\/\2)", re.IGNORECASE)

# Sensitive data patterns
sensitive_data_patterns = {
    'google_api': re.compile(r'AIza[0-9A-Za-z-_]{35}', re.IGNORECASE),
    'firebase': re.compile(r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', re.IGNORECASE),
    'google_captcha': re.compile(r'6L[0-9A-Za-z-_]{38}|^6[0-9a-zA-Z_-]{39}$', re.IGNORECASE),
    'google_oauth': re.compile(r'ya29\.[0-9A-Za-z\-_]+', re.IGNORECASE),
    'amazon_aws_access_key_id': re.compile(r'A[SK]IA[0-9A-Z]{16}', re.IGNORECASE),
    'amazon_mws_auth_toke': re.compile(r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.IGNORECASE),
    'amazon_aws_url': re.compile(r's3\.amazonaws\.com[/]+|[a-zA-Z0-9_-]*\.s3\.amazonaws\.com', re.IGNORECASE),
    'amazon_aws_url2': re.compile(
        r"[a-zA-Z0-9-\.\_]+\.s3\.amazonaws\.com|s3://[a-zA-Z0-9-\.\_]+|s3-[a-zA-Z0-9-\.\_\/]+|s3.amazonaws.com/[a-zA-Z0-9-\.\_]+|s3.console.aws.amazon.com/s3/buckets/[a-zA-Z0-9-\.\_]+",
        re.IGNORECASE
    ),
    'facebook_access_token': re.compile(r'EAACEdEose0cBA[0-9A-Za-z]+', re.IGNORECASE),
    'authorization_basic': re.compile(r'basic [a-zA-Z0-9=:_\+\/-]{5,100}', re.IGNORECASE),
    'authorization_bearer': re.compile(r'bearer [a-zA-Z0-9_\-\.=:_\+\/]{5,100}', re.IGNORECASE),
    'authorization_api': re.compile(r'api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}', re.IGNORECASE),
    'mailgun_api_key': re.compile(r'key-[0-9a-zA-Z]{32}', re.IGNORECASE),
    'twilio_api_key': re.compile(r'SK[0-9a-fA-F]{32}', re.IGNORECASE),
    'twilio_account_sid': re.compile(r'AC[a-zA-Z0-9_\-]{32}', re.IGNORECASE),
    'twilio_app_sid': re.compile(r'AP[a-zA-Z0-9_\-]{32}', re.IGNORECASE),
    'paypal_braintree_access_token': re.compile(r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}', re.IGNORECASE),
    'square_oauth_secret': re.compile(r'sq0csp-[ 0-9A-Za-z\-_]{43}|sq0[a-z]{3}-[0-9A-Za-z\-_]{22,43}', re.IGNORECASE),
    'square_access_token': re.compile(r'sqOatp-[0-9A-Za-z\-_]{22}|EAAA[a-zA-Z0-9]{60}', re.IGNORECASE),
    'stripe_standard_api': re.compile(r'sk_live_[0-9a-zA-Z]{24}', re.IGNORECASE),
    'stripe_restricted_api': re.compile(r'rk_live_[0-9a-zA-Z]{24}', re.IGNORECASE),
    'github_access_token': re.compile(r'[a-zA-Z0-9_-]*:[a-zA-Z0-9_\-]+@github\.com*', re.IGNORECASE),
    'rsa_private_key': re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.IGNORECASE),
    'ssh_dsa_private_key': re.compile(r'-----BEGIN DSA PRIVATE KEY-----', re.IGNORECASE),
    'ssh_ec_private_key': re.compile(r'-----BEGIN EC PRIVATE KEY-----', re.IGNORECASE),
    'pgp_private_block': re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', re.IGNORECASE),
    'json_web_token': re.compile(r'ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$', re.IGNORECASE),
    'slack_token': re.compile(r'"api_token":"(xox[a-zA-Z]-[a-zA-Z0-9-]+)"', re.IGNORECASE),
    'ssh_priv_key': re.compile(r'[-]+BEGIN [^\s]+ PRIVATE KEY[-]+[\s]*[^-]*[-]+END [^\s]+ PRIVATE KEY[-]+', re.IGNORECASE),
    'heroku_api_key': re.compile(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', re.IGNORECASE),
    'possible_creds': re.compile(r"(?i)(password\s*[`=:\"]+\s*[^\s]+|password is\s*[`=:\"]*\s*[^\s]+|pwd\s*[`=:\"]*\s*[^\s]+|passwd\s*[`=:\"]+\s*[^\s]+)", re.IGNORECASE)
}

# Regular expression to validate URL format
url_regex = re.compile(r'^(http|https)://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/[^\s]*)?$')

def sanitize_url(url):
    # Check if URL is valid
    if not url_regex.match(url):
        raise BadRequest('Invalid URL format.')
    return url.strip()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/parse_urls', methods=['POST'])
def parse_urls():
    raw_urls = request.form.get('urls', '')
    urls = [sanitize_url(url) for url in raw_urls.splitlines() if sanitize_url(url)]

    results = []

    for url in urls:
        if url:
            try:
                response = requests.get(url)
                response.raise_for_status()
                content = response.text

                # Find direct API URLs
                direct_url_matches = url_pattern.findall(content)
                for api_url in direct_url_matches:
                    results.append({
                        'url': url,
                        'method': 'N/A',
                        'endpoint': api_url,
                        'data': 'Direct API URL'
                    })

                # Find sensitive information
                sensitive_info = []
                for key, pattern in sensitive_data_patterns.items():
                    matches = pattern.findall(content)
                    for match in matches:
                        sensitive_info.append(f"{key}: {match}")
                if sensitive_info:
                    results.append({
                        'url': url,
                        'sensitive_info': sensitive_info
                    })

            except requests.RequestException as e:
                results.append({
                    'url': url,
                    'error': f"Error fetching URL: {e}"
                })

    return jsonify({'results': results})

@app.route('/generate_pdf', methods=['POST'])
def generate_pdf():
    results = request.json.get('results', [])

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    for result in results:
        pdf.cell(200, 10, txt=f"URL: {result['url']}", ln=True)
        if 'error' in result:
            pdf.cell(200, 10, txt=f"Error: {result['error']}", ln=True)
        else:
            if 'endpoint' in result:
                pdf.cell(200, 10, txt=f"Endpoint: {result['endpoint']}", ln=True)
            if 'sensitive_info' in result:
                pdf.cell(200, 10, txt="Sensitive Information:", ln=True)
                for info in result['sensitive_info']:
                    pdf.cell(200, 10, txt=f"  - {info}", ln=True)
        pdf.ln(10)

    pdf_file = "endpoints_results.pdf"
    pdf.output(pdf_file)

    return send_file(pdf_file, as_attachment=True)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5443, debug=False)
