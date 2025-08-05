import asyncio
import json
import threading
import time
from typing import Optional, List, Tuple


BOT_FILE = 'bot_profiles.json'
TO_BLOCK_FILE = 'to_block.json'

async def block_ip(ip: str, port: Optional[int] = None):
    if port:
        cmd = [
            "sudo", "iptables", "-A", "INPUT", "-s", ip,
            "-p", "tcp", "--dport", str(port), "-j", "DROP"
        ]
    else:
        cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
    
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    stdout, stderr = await proc.communicate()
    
    if proc.returncode == 0:
        print(f" Blocked {ip}" + (f" on port {port}" if port else ""))
    else:
        print(f" Failed to block {ip}: {stderr.decode().strip()}")

async def save_rules():
    cmd = ["sudo", "netfilter-persistent", "save"]
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    _, stderr = await proc.communicate()
    if proc.returncode == 0:
        print("Rules saved persistently.")
    else:
        print(f"Failed to save rules: {stderr.decode().strip()}")

async def block_ips(ip_list: List[Tuple[str, Optional[int]]]):
    for ip, port in ip_list:
        await block_ip(ip, port)
    await save_rules()
       
def extract_and_save_ips():
    try:
        with open(BOT_FILE, 'r') as f:
            bot_data = json.load(f)
            

        # Filter only suspicious IPs
        suspicious_ips = [
            ip for ip, data in bot_data.items() if data.get("is_suspicious", False)
        ]

        ip_tuples = [(ip, None) for ip in suspicious_ips]  # Port is None

        if ip_tuples:
            # Save IPs to to_block.json
            with open(TO_BLOCK_FILE, 'w') as f:
                json.dump(suspicious_ips, f, indent=2)
            print(f"Extracted {len(ip_tuples)} suspicious IP(s): {suspicious_ips}")

            # Block the extracted IPs
            asyncio.run(block_ips(ip_tuples))

        # Clear bot.json
        with open(BOT_FILE, 'w') as f:
            json.dump({}, f)

    except Exception as e:
        print(f"Error in extract_and_save_ips: {e}")

def schedule_extraction(interval=2000):
    def loop():
        while True:
            extract_and_save_ips()
            
            time.sleep(interval)
            print("started extract_and_save_ips")
    threading.Thread(target=loop, daemon=True).start()