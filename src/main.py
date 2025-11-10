import hashlib
import time

def hash_block(block_data, nonce):
    """
    Simulates hashing a block with a given nonce.
    Bitcoin uses double SHA-256: SHA256(SHA256(data))
    """
    data = f"{block_data}{nonce}".encode('utf-8')
    first_hash = hashlib.sha256(data).digest()
    second_hash = hashlib.sha256(first_hash).hexdigest()
    return second_hash

def mine_block(block_data, difficulty=4):
    """
    Tries to find a nonce that produces a hash with 'difficulty' leading zeros.
    
    Args:
        block_data: String representing block data
        difficulty: Number of leading zeros required (1-10 recommended for demo)
    
    Returns:
        tuple: (nonce, hash, attempts, time_taken)
    """
    target = "0" * difficulty  # e.g., "0000" for difficulty 4
    nonce = 0
    attempts = 0
    start_time = time.time()
    
    print(f"Mining started...")
    print(f"Target: Hash must start with '{target}'")
    print(f"Block data: {block_data}\n")
    
    while True:
        attempts += 1
        block_hash = hash_block(block_data, nonce)
        
        # Show progress every 100,000 attempts
        if attempts % 100000 == 0:
            print(f"Attempt {attempts:,}: nonce={nonce}, hash={block_hash[:20]}...")
        
        # Check if hash meets difficulty requirement
        if block_hash.startswith(target):
            time_taken = time.time() - start_time
            return nonce, block_hash, attempts, time_taken
        
        nonce += 1
        
        # Safety limit to prevent infinite loop
        if attempts > 100000000:
            print("Reached maximum attempts limit!")
            return None, None, attempts, time.time() - start_time

# Example usage
if __name__ == "__main__":
    # Simulate a simple block
    block_data = "Previous_Hash:0000abcd1234|Transactions:Alice->Bob:1BTC|Timestamp:1699632000|"
    
    # Try different difficulty levels
    # Note: difficulty > 6 can take a VERY long time!
    difficulty = 5  # Adjust this (1-6 recommended for quick demo)
    
    print("="*60)
    print("BITCOIN MINING SIMULATOR")
    print("="*60)
    
    nonce, block_hash, attempts, time_taken = mine_block(block_data, difficulty)
    
    if nonce is not None:
        print("\n" + "="*60)
        print("✅ BLOCK MINED SUCCESSFULLY!")
        print("="*60)
        print(f"Winning nonce: {nonce}")
        print(f"Block hash: {block_hash}")
        print(f"Total attempts: {attempts:,}")
        print(f"Time taken: {time_taken:.2f} seconds")
        print(f"Hash rate: {attempts/time_taken:,.0f} hashes/second")
        print("="*60)
        
        # Verify the result
        print("\nVerification:")
        verify_hash = hash_block(block_data, nonce)
        print(f"Recalculated hash: {verify_hash}")
        print(f"Matches: {verify_hash == block_hash} ✓")
    else:
        print("\n❌ Mining failed - reached attempt limit")
    
    # Show what real Bitcoin mining looks like
    print("\n" + "="*60)
    print("REAL BITCOIN COMPARISON")
    print("="*60)
    print(f"Your hash rate: ~{attempts/time_taken if time_taken > 0 else 0:,.0f} H/s")
    print(f"Modern ASIC miner: ~100,000,000,000,000 H/s (100 TH/s)")
    print(f"Entire Bitcoin network: ~500,000,000,000,000,000,000 H/s (500 EH/s)")
    print(f"Current Bitcoin difficulty requires ~19 leading zeros!")
    print("="*60)
