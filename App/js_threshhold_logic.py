# pow.py
import hashlib, random, string
from flask import jsonify, request

challenge_store = {}  # Store challenges per session or IP

def generate_challenge():
    challenge = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    difficulty = get_dynamic_difficulty()
    challenge_store[challenge] = difficulty
    return challenge, difficulty

def get_dynamic_difficulty():

    return 4

def pow_routes(app):
    @app.route('/api/pow-challenge')
    def pow_challenge():
        challenge, difficulty = generate_challenge()
        return jsonify({'challenge': challenge, 'difficulty': difficulty})

    @app.route('/api/pow-submit', methods=['POST'])
    def pow_submit():
        data = request.json
        challenge = data.get('challenge')
        nonce = str(data.get('nonce'))

        difficulty = challenge_store.get(challenge)
        if not difficulty:
            return jsonify({'status': 'invalid challenge'}), 400

        test_hash = hashlib.sha256((challenge + nonce).encode()).hexdigest()
        if test_hash.startswith('0' * difficulty):
            return jsonify({'status': 'verified'})
        return jsonify({'status': 'invalid proof'}), 403
