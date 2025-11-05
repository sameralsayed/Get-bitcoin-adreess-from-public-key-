#!/usr/bin/env python3
import hashlib
import base58   # pip install base58

# ------------------------------------------------------------
# 1. Helper: SHA-256 → RIPEMD-160
def hash160(data: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(data).digest()).digest()

# ------------------------------------------------------------
# 2. Public-key → address (P2PKH, mainnet)
def pubkey_to_address(pubkey_hex: str) -> str:
    """
    Convert a hex-encoded public key (compressed or uncompressed)
    into a legacy P2PKH Bitcoin address (starts with '1').
    
    Parameters
    ----------
    pubkey_hex : str
        Hex string of the public key, e.g.
        - uncompressed: 65 bytes → 130 hex chars
        - compressed  : 33 bytes → 66 hex chars
    
    Returns
    -------
    str
        Base58Check-encoded address.
    """
    pubkey = bytes.fromhex(pubkey_hex.strip())
    
    # ---- detect compressed / uncompressed ----
    if len(pubkey) == 65 and pubkey[0] == 0x04:
        # uncompressed: 0x04 + X (32) + Y (32)
        pass
    elif len(pubkey) == 33 and pubkey[0] in (0x02, 0x03):
        # already compressed
        pass
    else:
        raise ValueError("Invalid public key length or prefix")
    
    # ---- hash160(public_key) ----
    h160 = hash160(pubkey)                     # 20 bytes
    
    # ---- version byte 0x00 for mainnet P2PKH ----
    payload = b'\x00' + h160
    
    # ---- checksum (first 4 bytes of SHA256(SHA256(payload))) ----
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    
    # ---- Base58Check encode ----
    address = base58.b58encode(payload + checksum).decode()
    return address

# ------------------------------------------------------------
# 3. Example usage
if __name__ == "__main__":
    # Example 1 – uncompressed (65-byte) pubkey
    uncompressed = (
        "04"
        "50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
        "2cd470243453a299fa9e77237716103abc11a1df38855ed6f2ee187e9c582ba6"
    )
    print("Uncompressed →", pubkey_to_address(uncompressed))
    # → 16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM
    
    # Example 2 – compressed (33-byte) pubkey
    compressed = "02" + "50863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352"
    print("Compressed   →", pubkey_to_address(compressed))
    # → 1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs