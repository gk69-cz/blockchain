from hashlib import sha256
import json
import os
import time
from flask import Flask, request

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = None  # Ensure it's part of the block by default

    def compute_hash(self):
        block_data = {
            'index': self.index,
            'transactions': self.transactions,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce
        }
        block_string = json.dumps(block_data, sort_keys=True)
        return sha256(block_string.encode()).hexdigest()

    def to_dict(self):
        return {
            'index': self.index,
            'transactions': self.transactions,
            'timestamp': self.timestamp,
            'previous_hash': self.previous_hash,
            'nonce': self.nonce,
            'hash': self.hash
        }

    @classmethod
    def from_dict(cls, block_data):
        block = cls(
            block_data['index'],
            block_data['transactions'],
            block_data['timestamp'],
            block_data['previous_hash'],
            block_data['nonce']
        )
        block.hash = block_data.get('hash')
        return block

class Blockchain:
    difficulty = 2

    def __init__(self):
        self.blockchain_file = "blockchain.json"
        self.unconfirmed_transactions = []
        self.chain = []
        self.load_blockchain()

    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "0")
        genesis_block.hash = self.proof_of_work(genesis_block)
        self.chain.append(genesis_block)
        self.save_blockchain()

    def load_blockchain(self):
        if os.path.exists(self.blockchain_file):
            try:
                with open(self.blockchain_file, 'r') as f:
                    blockchain_data = json.load(f)
                for block_data in blockchain_data['chain']:
                    block = Block.from_dict(block_data)
                    self.chain.append(block)
                self.unconfirmed_transactions = blockchain_data.get('pending_transactions', [])
                print(f"Blockchain loaded: {len(self.chain)} blocks")
            except (json.JSONDecodeError, KeyError, FileNotFoundError) as e:
                print(f"Error loading blockchain: {e}")
                self.create_genesis_block()
        else:
            print("No existing blockchain found. Creating genesis block...")
            self.create_genesis_block()

    def save_blockchain(self):
        try:
            blockchain_data = {
                'chain': [block.to_dict() for block in self.chain],
                'pending_transactions': self.unconfirmed_transactions,
                'last_updated': time.time()
            }
            temp_file = self.blockchain_file + '.tmp'
            with open(temp_file, 'w') as f:
                json.dump(blockchain_data, f, indent=2)
            os.replace(temp_file, self.blockchain_file)
            print(f"Blockchain saved: {len(self.chain)} blocks")
        except Exception as e:
            print(f"Error saving blockchain: {e}")

    @property
    def last_block(self):
        return self.chain[-1]

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = block.compute_hash()
        while not computed_hash.startswith('0' * Blockchain.difficulty):
            block.nonce += 1
            computed_hash = block.compute_hash()
        return computed_hash

    def add_block(self, block, proof):
        previous_hash = self.last_block.hash
        if previous_hash != block.previous_hash:
            return False
        if not self.is_valid_proof(block, proof):
            return False
        block.hash = proof
        self.chain.append(block)
        self.save_blockchain()  # ✅ Save chain after adding block
        return True

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * Blockchain.difficulty) and
                block_hash == block.compute_hash())

    def add_new_transaction(self, transaction):
        self.unconfirmed_transactions.append(transaction)

    def mine(self):
        if not self.unconfirmed_transactions:
            return False
        last_block = self.last_block
        new_block = Block(index=last_block.index + 1,
                          transactions=self.unconfirmed_transactions,
                          timestamp=time.time(),
                          previous_hash=last_block.hash)
        proof = self.proof_of_work(new_block)
        added = self.add_block(new_block, proof)
        if added:
            self.unconfirmed_transactions = []
            return new_block.index
        return False

    def search_content(self, term):
        matches = []
        for block in self.chain:
            for tx in block.transactions:
                if term.lower() in str(tx).lower():
                    matches.append({
                        'block_index': block.index,
                        'transaction': tx
                    })
        return matches

app = Flask(__name__)
blockchain = Blockchain()

@app.route('/chain', methods=['GET'])
def get_chain():
    chain_data = [block.to_dict() for block in blockchain.chain]
    return json.dumps({"length": len(chain_data), "chain": chain_data}, indent=2)

@app.route('/new_transaction', methods=['POST'])
def new_transaction():
    tx_data = request.get_json()
    required_fields = ["iphash", "content"]
    for field in required_fields:
        if not tx_data.get(field):
            return "Invalid transaction data", 400
    tx_data["timestamp"] = time.time()
    blockchain.add_new_transaction(tx_data)
    return "Success", 201

@app.route('/mine', methods=['GET'])
def mine_unconfirmed_transactions():
    result = blockchain.mine()
    if not result:
        return "No transactions to mine"
    else:
        return f"Block #{result} is mined."

@app.route('/pending_tx')
def get_pending_tx():
    return json.dumps(blockchain.unconfirmed_transactions, indent=2)

@app.route('/search/<search_term>')
def search_blockchain(search_term):
    results = blockchain.search_content(search_term)
    if not results:
        return json.dumps({
            "found": False,
            "message": f"No content found for '{search_term}'",
            "results": []
        })
    return json.dumps({
        "found": True,
        "total_matches": len(results),
        "search_term": search_term,
        "results": results
    }, indent=2)

@app.route('/search', methods=['POST'])
def search_blockchain_post():
    search_data = request.get_json()
    search_term = search_data.get('search_term', '')
    if not search_term:
        return "Search term is required", 400
    results = blockchain.search_content(search_term)
    if not results:
        return json.dumps({
            "found": False,
            "message": f"No content found for '{search_term}'",
            "results": []
        })
    return json.dumps({
        "found": True,
        "total_matches": len(results),
        "search_term": search_term,
        "results": results
    }, indent=2)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
