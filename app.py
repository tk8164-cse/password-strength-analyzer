from flask import Flask, render_template, request, jsonify
import hashlib
import re

app = Flask(__name__)

def evaluate_password(password):
    """Evaluates password complexity and returns a score (0-4) along with suggestions."""
    score = 0
    improvements = []
    warnings = []

    # 1. Check for common weak patterns
    if re.match(r'^[0-9]+$', password):
        warnings.append("Password consists only of numbers.")
    if re.match(r'^[a-zA-Z]+$', password):
        warnings.append("Password consists only of letters.")
    if password.lower() in ["password", "123456", "qwerty", "admin"]:
        warnings.append("Commonly used, easily guessable password.")

    # 2. Complexity Rules (Systems Engineering Scoring)
    if len(password) >= 12:
        score += 1
    else:
        improvements.append("Increase length to 12 or more characters.")

    if re.search(r'[A-Z]', password) and re.search(r'[a-z]', password):
        score += 1
    else:
        improvements.append("Mix both uppercase and lowercase letters.")

    if re.search(r'[0-9]', password):
        score += 1
    else:
        improvements.append("Add at least one numerical digit.")

    if re.search(r'[^a-zA-Z0-9]', password):
        score += 1
    else:
        improvements.append("Add special characters (e.g., !, @, #).")

    # Treat catastrophic weak patterns by capping the score
    if warnings and score > 1:
        score = 1

    return score, warnings, improvements

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    data = request.get_json()
    password = data.get('password', '')

    if not password:
        return jsonify({"error": "Empty password"}), 400

    # Calculate metrics internally without third-party zxcvbn
    score, warnings, improvements = evaluate_password(password)

    # Cryptographic Hashing Simulation (Secure Identity Management)
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()

    return jsonify({
        "score": score,
        "warnings": warnings,
        "improvements": improvements if improvements else ["Your password matches security standards!"],
        "hash_preview": sha256_hash
    })

if __name__ == '__main__':
    app.run(debug=True)