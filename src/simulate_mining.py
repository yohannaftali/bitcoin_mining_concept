import hashlib
import time
import struct
import random

class BitcoinMiner:
    """
    A realistic Bitcoin mining simulator that mimics actual Bitcoin block structure.
    """
    
    def __init__(self):
        # Bitcoin uses 32-bit nonce (0 to 4,294,967,295)
        self.max_nonce = 2**32
    
    def create_block_header(self, version, prev_block_hash, merkle_root, timestamp, bits, nonce):
        """
        Create a Bitcoin block header (80 bytes total).
        
        Structure:
        - Version: 4 bytes
        - Previous Block Hash: 32 bytes
        - Merkle Root: 32 bytes
        - Timestamp: 4 bytes
        - Bits (difficulty target): 4 bytes
        - Nonce: 4 bytes
        """
        header = b''
        header += struct.pack('<L', version)  # Little-endian 4-byte integer
        header += bytes.fromhex(prev_block_hash)[::-1]  # Reverse byte order
        header += bytes.fromhex(merkle_root)[::-1]
        header += struct.pack('<L', timestamp)
        header += struct.pack('<L', bits)
        header += struct.pack('<L', nonce)
        
        return header
    
    def double_sha256(self, data):
        """
        Perform double SHA-256 hashing (Bitcoin's standard).
        Returns the hash in hexadecimal format.
        """
        first_hash = hashlib.sha256(data).digest()
        second_hash = hashlib.sha256(first_hash).digest()
        # Reverse byte order for display (Bitcoin convention)
        return second_hash[::-1].hex()
    
    def bits_to_target(self, bits):
        """
        Convert compact 'bits' representation to full target value.
        Bits format: 0x1d00ffff (example)
        """
        exponent = bits >> 24
        mantissa = bits & 0xffffff
        if exponent <= 3:
            target = mantissa >> (8 * (3 - exponent))
        else:
            target = mantissa << (8 * (exponent - 3))
        return target
    
    def hash_meets_target(self, hash_hex, target):
        """
        Check if the hash value is less than the target.
        """
        hash_int = int(hash_hex, 16)
        return hash_int < target
    
    def mine_block(self, version, prev_block_hash, merkle_root, timestamp, bits, 
                   max_attempts=None, show_progress=True):
        """
        Mine a block by finding a valid nonce.
        
        Args:
            version: Block version number
            prev_block_hash: Previous block's hash (64 hex chars)
            merkle_root: Merkle root of transactions (64 hex chars)
            timestamp: Unix timestamp
            bits: Difficulty target in compact format
            max_attempts: Maximum nonces to try (None = try all 4 billion)
            show_progress: Show mining progress
        
        Returns:
            dict with mining results
        """
        target = self.bits_to_target(bits)
        target_hex = format(target, '064x')
        
        print("="*70)
        print("REALISTIC BITCOIN MINING SIMULATION")
        print("="*70)
        print(f"Block Version: {version}")
        print(f"Previous Block: {prev_block_hash[:16]}...{prev_block_hash[-16:]}")
        print(f"Merkle Root: {merkle_root[:16]}...{merkle_root[-16:]}")
        print(f"Timestamp: {timestamp} ({time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(timestamp))})")
        print(f"Bits (difficulty): 0x{bits:08x}")
        print(f"Target: {target_hex}")
        print(f"Required: Hash must be < Target")
        print("="*70)
        print("\nMining started...\n")
        
        attempts = 0
        start_time = time.time()
        nonce = 0
        
        max_nonce = max_attempts if max_attempts else self.max_nonce
        
        while nonce < max_nonce:
            attempts += 1
            
            # Create block header with current nonce
            header = self.create_block_header(
                version, prev_block_hash, merkle_root, 
                timestamp, bits, nonce
            )
            
            # Calculate hash
            block_hash = self.double_sha256(header)
            
            # Show progress
            if show_progress and attempts % 500000 == 0:
                elapsed = time.time() - start_time
                hash_rate = attempts / elapsed if elapsed > 0 else 0
                print(f"Attempt {attempts:,} | Nonce: {nonce:,} | "
                      f"Hash rate: {hash_rate:,.0f} H/s | "
                      f"Hash: {block_hash[:32]}...")
            
            # Check if hash meets target
            if self.hash_meets_target(block_hash, target):
                time_taken = time.time() - start_time
                
                print("\n" + "="*70)
                print("✅ VALID BLOCK FOUND!")
                print("="*70)
                print(f"Winning Nonce: {nonce:,}")
                print(f"Block Hash: {block_hash}")
                print(f"Target:     {target_hex}")
                print(f"Hash < Target: ✓")
                print(f"\nTotal Attempts: {attempts:,}")
                print(f"Time Taken: {time_taken:.2f} seconds")
                print(f"Hash Rate: {attempts/time_taken:,.0f} H/s")
                print("="*70)
                
                return {
                    'success': True,
                    'nonce': nonce,
                    'hash': block_hash,
                    'attempts': attempts,
                    'time': time_taken,
                    'hash_rate': attempts/time_taken
                }
            
            nonce += 1
        
        # Failed to find valid nonce
        time_taken = time.time() - start_time
        print(f"\n❌ No valid nonce found in {attempts:,} attempts")
        print(f"Time: {time_taken:.2f} seconds")
        
        return {
            'success': False,
            'attempts': attempts,
            'time': time_taken
        }

def example_easy_mining():
    """
    Example 1: Easy mining (simulated low difficulty)
    """
    miner = BitcoinMiner()
    
    # Simulate an easy difficulty (much easier than real Bitcoin)
    # bits = 0x1f00ffff means very low difficulty
    result = miner.mine_block(
        version=0x20000000,
        prev_block_hash='0000000000000000000' + '1' * 45,  # Simulated previous hash
        merkle_root='a' * 64,  # Simulated merkle root
        timestamp=int(time.time()),
        bits=0x1f00ffff,  # VERY easy difficulty
        max_attempts=10000000,  # Limit attempts for demo
        show_progress=True
    )
    
    return result

def example_real_difficulty():
    """
    Example 2: Attempt with REAL Bitcoin difficulty (will likely not find a block!)
    This demonstrates why you need specialized hardware.
    """
    miner = BitcoinMiner()
    
    print("\n" + "="*70)
    print("ATTEMPTING WITH REAL BITCOIN DIFFICULTY")
    print("="*70)
    print("⚠️  Warning: With real difficulty, finding a block would take")
    print("    millions of years on a regular computer!")
    print("    This demo will try 10 million nonces then stop.\n")
    
    # Real Bitcoin difficulty as of 2024 (approximately)
    # bits = 0x17034219 (example from recent blocks)
    result = miner.mine_block(
        version=0x20000000,
        prev_block_hash='00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72728a054',
        merkle_root='7d8e9c2b1f4a6e8d5c3b9a2f1e8d7c6b5a4e3d2c1b9a8f7e6d5c4b3a2e1d0c9b',
        timestamp=int(time.time()),
        bits=0x17034219,  # REAL Bitcoin difficulty
        max_attempts=10000000,  # Try 10 million then give up
        show_progress=True
    )
    
    if not result['success']:
        print("\n💡 To find a block at real difficulty, you would need:")
        print("   • ASIC miners: ~100 TH/s (100 trillion hashes/second)")
        print("   • Multiple machines in a mining farm")
        print("   • Still might take days/weeks to find one block")
        print("   • Entire Bitcoin network: ~500 EH/s (500 quintillion H/s)")
    
    return result

# Run the examples
if __name__ == "__main__":
    print("Choose mining difficulty:")
    print("1. Easy difficulty (will find a block quickly)")
    print("2. REAL Bitcoin difficulty (educational - won't find a block)\n")
    
    # Run easy example by default
    print("Running EASY difficulty example...\n")
    result1 = example_easy_mining()
    
    # Uncomment below to try real difficulty (educational only)
    # print("\n\nPress Enter to try REAL difficulty (educational)...")
    # input()
    # result2 = example_real_difficulty()
