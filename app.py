# app.py
from flask import Flask, request, abort
from waf import is_malicious_request, log_attack, is_rate_limited
from flask import render_template

app = Flask(__name__)

@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html", message=error.description), 403

@app.errorhandler(429)
def too_many_requests(error):
    return render_template("429.html", message=error.description), 429

@app.before_request
def check_for_malicious_content():
    ip = request.remote_addr
    user_agent = request.headers.get("User-Agent")
    
    if is_ip_whitelisted(ip):
        return
    if is_ip_blacklisted(ip):
        abort(403, description="Your IP has been blocked.")
    
    data = request.get_data(as_text=True)
    
    if is_rate_limited(ip):
        abort(429, description="Too many requests.")
    
    attack_type = is_malicious_request(data)
    if attack_type:
        log_attack(ip, attack_type, data, user_agent)
        abort(403, description="Malicious activity detected.")
    
    anomaly = is_anomalous_request(data)
    if anomaly:
        log_attack(ip, anomaly, data, user_agent)
        abort(403, description="Anomalous activity detected.")


@app.route('/')
def home():
    return "Welcome to the protected web application!"

@app.route('/submit', methods=['POST'])
def submit_data():
    # Simulate data submission endpoint
    return "Data submitted successfully."

if __name__ == '__main__':
    app.run(port=5000)
