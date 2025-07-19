import urllib.request
import urllib.parse
import json

def submit_transaction_to_blockchain(ip_address, headers_present, ttl_obfuscation, legitimacy_score, is_trustworthy):

    new_transaction = {
            "ip": ip_address,
            "headers_present": headers_present,
            "ttl_obfuscation": ttl_obfuscation,
            "legitimacy_score": legitimacy_score,
            "is_trustworthy": is_trustworthy
        }
    