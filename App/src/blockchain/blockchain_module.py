from hashlib import sha256
import json
import os
import time

class Block:
    def __init__(self, index, transactions, timestamp, previous_hash, nonce=0):
        self.index = index
        self.transactions = transactions
        self.timestamp = timestamp
        self.previous_hash = previous_hash
        self.nonce = nonce
        self.hash = None

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
    def __init__(self, blockchain_file="blockchain.json", difficulty=4):
        self.blockchain_file = blockchain_file
        self.difficulty = difficulty
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
        while not computed_hash.startswith('0' * self.difficulty):
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
        self.save_blockchain()
        return True

    def is_valid_proof(self, block, block_hash):
        return (block_hash.startswith('0' * self.difficulty) and
                block_hash == block.compute_hash())

    def check_ip_exists(self, ip_address):
        """Check if an IP address exists in pending transactions"""
        for tx in self.unconfirmed_transactions:
            if tx.get("ip") == ip_address:
                return True
        return False
    def add_transaction(self, transaction):
        """Add a new transaction to the pending transactions"""
        required_fields = ["ip", "headers_present", "ttl_obfuscation", "legitimacy_score", "is_trustworthy"]
        for field in required_fields:
            if field not in transaction:
                raise ValueError(f"Missing required field: {field}")

        if not isinstance(transaction.get("ip"), str):
            raise ValueError("Invalid IP format")

        if not isinstance(transaction.get("legitimacy_score"), (int, float)):
            raise ValueError("Invalid legitimacy_score format")

        if not isinstance(transaction.get("is_trustworthy"), bool):
            raise ValueError("Invalid is_trustworthy format")

        # Check if IP already exists in pending transactions
        ip_address = transaction.get("ip")
        for existing_tx in self.unconfirmed_transactions:
            if existing_tx.get("ip") == ip_address:
                # Update existing transaction instead of adding duplicate
                existing_tx.update(transaction)
                existing_tx["timestamp"] = time.time()
                print(f"Transaction updated for IP: {ip_address}")
                return True
            
        transaction["timestamp"] = time.time()
        self.unconfirmed_transactions.append(transaction)
        print(f"Transaction added: {transaction}")
        return True

    def mine(self):
        """Mine pending transactions into a new block with unique IP addresses"""
        if not self.unconfirmed_transactions:
            return False

        seen_ips = set()
        unique_transactions = []

        for tx in self.unconfirmed_transactions:
            ip = tx.get("ip")
            if ip:
                if ip in seen_ips:
                    continue  # skip duplicates
                if self.check_ip_exists(ip):  # redundant since it's from unconfirmed
                    seen_ips.add(ip)
                    unique_transactions.append(tx)
            else:
                # If transaction has no IP (like system/internal tx), always include
                unique_transactions.append(tx)

        if not unique_transactions:
            return False

        # Add miner metadata
        hex_key = os.urandom(8).hex()
        unique_transactions.append({'mined_by_key': hex_key})

        last_block = self.last_block
        new_block = Block(
            index=last_block.index + 1,
            transactions=unique_transactions,
            timestamp=time.time(),
            previous_hash=last_block.hash
        )

        proof = self.proof_of_work(new_block)

        if self.add_block(new_block, proof):
            self.unconfirmed_transactions = []
            return {
                "index": new_block.index,
                "hex_key": hex_key
            }

        return False

    def get_chain(self):
        """Get the entire blockchain"""
        return {
            "length": len(self.chain),
            "chain": [block.to_dict() for block in self.chain]
        }

    def get_pending_transactions(self):
        """Get all pending transactions"""
        return {
            "pending_transactions": self.unconfirmed_transactions,
            "count": len(self.unconfirmed_transactions)
        }

    def search_by_ip(self, ip_address):
        """Search for transactions containing a specific IP address"""
        matches = []

        for tx in self.unconfirmed_transactions:
            if tx.get('ip') == ip_address:
                matches.append({
                    'type': 'pending',
                    'transaction': tx
                })

        for block in self.chain:
            for tx in block.transactions:
                if isinstance(tx, dict) and tx.get('ip') == ip_address:
                    matches.append({
                        'type': 'confirmed',
                        'block_index': block.index,
                        'transaction': tx
                    })

        return {
            "found": len(matches) > 0,
            "total_matches": len(matches),
            "search_term": ip_address,
            "results": matches
        }
