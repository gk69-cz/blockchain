from flask import Flask, request, jsonify
from blockchain_module import Blockchain  # Replace with actual import

# Initialize Blockchain
blockchain = Blockchain(difficulty=3)

# Initialize Flask App
app = Flask(__name__)

# -----------------------------
# Blockchain API Functions
# -----------------------------

@app.route('/api/blockchain/add-transaction', methods=['POST'])
def api_add_transaction():
    """Add a transaction to the blockchain"""
    tx_data = request.get_json()
    try:
        
        blockchain.add_transaction(tx_data)
        return jsonify({"message": "Transaction added successfully"}), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route('/api/blockchain/mine', methods=['GET'])
def api_mine():
    # to add more logic
    result = blockchain.mine()
    if result:
        return jsonify({
            "message": f"Block #{result['index']} mined successfully",
            "details": result
        }), 201
    else:
        return jsonify({"message": "No transactions to mine"}), 200

@app.route('/api/blockchain/usermine', methods=['GET'])
def api_mine():
    result = blockchain.usermine()
    if result:
        return jsonify({
            "message": f"Block #{result['index']} mined successfully",
            "details": result
        }), 201
    else:
        return jsonify({"message": "No transactions to mine"}), 200

@app.route('/api/blockchain/chain', methods=['GET'])
def api_get_chain():
    chain = blockchain.get_chain()
    return jsonify(chain), 200


@app.route('/api/blockchain/pending', methods=['GET'])
def api_get_pending_transactions():
    """Get all pending transactions"""
    pending = blockchain.get_pending_transactions()
    return jsonify(pending), 200


@app.route('/api/blockchain/search', methods=['POST'])
def api_search_by_ip():
    """Search for transactions using an IP"""
    data = request.get_json()
    ip = data.get("ip")
    if not ip:
        return jsonify({"error": "Missing 'ip' field in request"}), 400

    result = blockchain.search_by_ip(ip)
    return jsonify(result), 200

# -----------------------------
# Run Server
# -----------------------------

if __name__ == '__main__':
    app.run(port=5000, debug=True)
