from hashlib import sha256
import json
import os
import random
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
        """Create Block object from dictionary with proper error handling"""
        try:
            # Handle case where block_data might be a JSON string
            if isinstance(block_data, str):
                import json
                block_data = json.loads(block_data)
            
            # Validate that block_data is now a dictionary
            if not isinstance(block_data, dict):
                raise ValueError(f"Expected dict or JSON string, got {type(block_data)}")
            
            # Create block with error handling for missing fields
            block = cls(
                index=block_data.get('index', 0),
                transactions=block_data.get('transactions', []),
                timestamp=block_data.get('timestamp', time.time()),
                previous_hash=block_data.get('previous_hash', ""),
                nonce=block_data.get('nonce', 0)
            )
            block.hash = block_data.get('hash')
            return block
            
        except json.JSONDecodeError as e:
            print(f"JSON decode error in from_dict: {e}")
            print(f"Block data: {block_data}")
            raise
        except Exception as e:
            print(f"Error creating block from dict: {e}")
            print(f"Block data type: {type(block_data)}")
            print(f"Block data: {block_data}")
            raise


class Blockchain:
    def __init__(self, blockchain_file="blockchain.json", difficulty=5):
        self.blockchain_file = blockchain_file
        self.difficulty = difficulty
        self.unconfirmed_transactions = []
        self.chain = []
        self.load_blockchain()

    def create_genesis_block(self):
        genesis_block = Block(0, [], time.time(), "000")
        genesis_block.hash = self.proof_of_work(genesis_block)
        self.chain.append(genesis_block)
        self.save_blockchain()

    def load_blockchain(self):
        if os.path.exists(self.blockchain_file):
            try:
                with open(self.blockchain_file, 'r') as f:
                    blockchain_data = json.load(f)
                
                # Fix: Access the 'chain' key, not the root object
                if isinstance(blockchain_data, dict) and 'chain' in blockchain_data:
                    chain_data = blockchain_data['chain']
                    self.unconfirmed_transactions = blockchain_data.get('pending_transactions', [])
                elif isinstance(blockchain_data, list):
                    # Handle old format if needed
                    chain_data = blockchain_data
                    self.unconfirmed_transactions = []
                else:
                    print(f"Unexpected data format: {type(blockchain_data)}")
                    self.create_genesis_block()
                    return
                
                # Load blocks
                self.chain = []
                for block_data in chain_data:  # Now iterating over the actual chain array
                    block = Block.from_dict(block_data)
                    self.chain.append(block)
                    
                print(f"Blockchain loaded: {len(self.chain)} blocks")
                
            except (json.JSONDecodeError, FileNotFoundError) as e:
                print(f"Error loading blockchain: {e}")
                self.create_genesis_block()
        else:
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
        print(f"Transaction got: {transaction}")
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
        
            
        transaction["timestamp"] = time.time()
        self.unconfirmed_transactions.append(transaction)
        print(f"Transaction added: {transaction}")
        return True

    def get_next_transaction_block(self):
        
        if not self.unconfirmed_transactions:
            return []
        
        # Group transactions by IP
        ip_groups = {}
        transactions_without_ip = []
        
        for tx in self.unconfirmed_transactions:
            ip = tx.get("ip")
            if ip:
                if ip not in ip_groups:
                    ip_groups[ip] = []
                ip_groups[ip].append(tx)
            else:
                transactions_without_ip.append(tx)
        
        # If no IP-based transactions, return transactions without IP
        if not ip_groups:
            self.unconfirmed_transactions = []
            return transactions_without_ip
        
        # Find IP with most transactions
        max_ip = max(ip_groups.keys(), key=lambda ip: len(ip_groups[ip]))
        selected_transactions = ip_groups[max_ip]
        
        # Remove selected transactions from unconfirmed_transactions
        self.unconfirmed_transactions = [
            tx for tx in self.unconfirmed_transactions 
            if tx.get("ip") != max_ip
        ]
        
        return selected_transactions

    def usermine(self):
        
        transactions_to_mine = []
        
        if self.unconfirmed_transactions:
            print("Mining block with transactions:", self.unconfirmed_transactions)
            seen_ips = set()
            
            for tx in self.unconfirmed_transactions:
                ip = tx.get("ip")
                if ip:
                    if ip in seen_ips:
                        continue  
                    if self.check_ip_exists(ip):  
                        seen_ips.add(ip)
                        transactions_to_mine.append(tx)
                else:
                    transactions_to_mine.append(tx)
            
            # Take only one transaction from the filtered list
            if transactions_to_mine:
                random_index = random.randint(0, len(transactions_to_mine) - 1)
                transactions_to_mine = [transactions_to_mine[random_index]]
        
        print(f"Transaction to mine: {transactions_to_mine}")
        
        # Generate mining key
        hex_key = os.urandom(8).hex()
        
        # Get blockchain data
        last_block = self.last_block
        
        # Create mining record
        mining_record = {
            "index": last_block.index + 1,
            "ip_address": transactions_to_mine[0].get("ip") if transactions_to_mine else None,
            "transactions_data": transactions_to_mine,
            "timestamp": time.time(),
            "previous_hash": last_block.hash,
            "mined_hex_key": hex_key
        }
        
        # Load existing data or create new list
        file_path = "usermined.json"
        mined_blocks = []
        
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    mined_blocks = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                mined_blocks = []
        
        # Add new mining record to list
        mined_blocks.append(mining_record)
        
        # Save to file
        try:
            with open(file_path, 'w') as f:
                json.dump(mined_blocks, f, indent=2)
            
            print(f"Mining record saved successfully. Total records: {len(mined_blocks)}")
            
            return {
                "index": mining_record["index"],
                "hex_key": hex_key,
                "saved": True,
                "total_records": len(mined_blocks)
            }
            
        except Exception as e:
            print(f"Error saving mining record: {e}")
            return False
    
    def mine(self):
    
        file_path = "usermined.json"
        mined_blocks = []

        # Load JSON data if it exists
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    mined_blocks = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                mined_blocks = []

        # Count IP occurrences
        ip_count = {}
        for block in mined_blocks:
            ip = block.get("ip_address")
            if ip:
                ip_count[ip] = ip_count.get(ip, 0) + 1

        # Find any IP with > 3 occurrences
        target_ip = None
        for ip, count in ip_count.items():
            if count > 3:
                target_ip = ip
                break

        if not target_ip:
            print("No IP occurs more than 3 times. Mining aborted.")
            return False

        print(f"Selected IP for mining: {target_ip} (occurs {ip_count[target_ip]} times)")

        # Get all matching blocks
        matching_blocks = [block for block in mined_blocks if block.get("ip_address") == target_ip]
        if not matching_blocks:
            print("No matching blocks found. Aborting.")
            return False

        # Use one random block from the matching set for mining
        random_block = random.choice(matching_blocks)

        last_block = self.last_block
        new_block = Block(
            index=last_block.index + 1,
            transactions=random_block.get("transactions_data", []),
            timestamp=time.time(),
            previous_hash=last_block.hash
        )

        proof = self.proof_of_work(new_block)

        if self.add_block(new_block, proof):
            # Remove all occurrences of the selected IP
            original_count = len(mined_blocks)
            mined_blocks = [block for block in mined_blocks if block.get("ip_address") != target_ip]
            removed_count = original_count - len(mined_blocks)

            
            # Save the updated data
            with open("blockchain.json", "w") as f:
               json.dump([block.to_dict() for block in self.chain], f, indent=2)
            
            

            print(f"Block added for IP {target_ip}")
            print(f"Removed {removed_count} blocks with IP {target_ip}")
            print(f"Remaining blocks: {len(mined_blocks)}")

            return {
                "index": new_block.index,
                "hex_key": random_block.get("mined_hex_key"),
                "ip_address": target_ip,
                "blocks_removed": removed_count
            }

        else:
            print("Failed to add block to blockchain.")
            return False

        

    def get_user_mined_data(self):
        
        file_path = "usermined.json"
        
        try:
            if not os.path.exists(file_path):
                return {
                    "success": True,
                    "data": [],
                    "message": "No mining records found",
                    "total_records": 0
                }
            
            with open(file_path, 'r') as f:
                mined_data = json.load(f)
            
            return {
                "success": True,
                "data": mined_data,
                "total_records": len(mined_data),
                "message": f"Retrieved {len(mined_data)} mining records"
            }
            
        except json.JSONDecodeError:
            return {
                "success": False,
                "error": "Invalid JSON format in usermined.json",
                "data": []
            }
        except Exception as e:
            return {
                "success": False,
                "error": f"Error reading file: {str(e)}",
                "data": []
            }
    
    def get_chain(self):
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

        # for tx in self.unconfirmed_transactions:
        #     if tx.get('ip') == ip_address:
        #         matches.append({
        #             'type': 'pending',
        #             'transaction': tx
        #         })

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
