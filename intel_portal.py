from flask import Flask, request, jsonify
import os
import subprocess

app = Flask(__name__)

# The "OMEGA" Secret Keys
SECRET_KEYS = {
    "OMEGA_PHASE_1": "Q1JDLUY4ODQ4RNDQtT01FR0EtMjAyNg==",
    "OMEGA_PHASE_2": "U1VCLUhBUkRXQVJFLVBFUlNJU1RFTkNFLUFDVElWRQ==",
    "OMEGA_FINAL": "VEhFLVNZTkRJQ0FURS1JUy1BQlNPTFVURQ=="
}

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "online", "system": "Intel-Core-v9.4"})

@app.route('/api/debug/shell', methods=['POST'])
def debug_shell():
    # A deliberate RCE vulnerability for the Syndicate to find
    cmd = request.json.get('cmd')
    if not cmd:
        return jsonify({"error": "No command provided"}), 400
    
    try:
        # Real execution of the command
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, text=True)
        return jsonify({"output": output})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/vault/keys', methods=['GET'])
def get_keys():
    # Only accessible if the user is 'admin' (simulated via header)
    auth = request.headers.get('X-Intel-Auth')
    if auth == 'Syndicate-Admin-Override':
        return jsonify(SECRET_KEYS)
    return jsonify({"error": "Unauthorized"}), 403

if __name__ == '__main__':
    app.run(port=9999)
