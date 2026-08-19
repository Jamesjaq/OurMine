from flask import Flask, request, jsonify
import subprocess
import os

app = Flask(__name__)

# A mock "Bank Admin API" with a real command injection vulnerability
@app.route('/api/v1/system/ping', methods=['GET'])
def ping_system():
    target = request.args.get('host', '127.0.0.1')
    # VULNERABILITY: Direct shell execution without sanitization
    try:
        # In a real scenario, this is where the attacker would inject: 127.0.0.1; cat /etc/passwd
        output = subprocess.check_output(f"ping -c 1 {target}", shell=True, stderr=subprocess.STDOUT)
        return jsonify({"status": "success", "output": output.decode()})
    except Exception as e:
        return jsonify({"status": "error", "output": str(e)}), 500

@app.route('/api/v1/vault/status', methods=['GET'])
def vault_status():
    return jsonify({
        "vault_id": "VAULT-SEC-099",
        "status": "locked",
        "balance": "1,250,000,000 USD",
        "last_audit": "2026-08-18"
    })

if __name__ == '__main__':
    # Running on a non-standard port to test discovery
    app.run(host='127.0.0.1', port=8888)
