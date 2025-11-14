"""
Utility functions ported from NerdMiner_v2 utils.cpp.

Provides helper functions for:
- Byte array conversions (hex to binary, endian swapping)
- Difficulty calculations from target
- Hash validation
- Extranonce2 generation (random/linear)
- CRC32 checksums
- String formatting with SI unit suffixes
"""

import struct
import hashlib


# ============================================================================
# Endianness and byte swapping
# ============================================================================

def bswap_16(value: int) -> int:
    """Swap bytes in 16-bit value."""
    return ((value << 8) & 0xff00) | ((value >> 8) & 0xff)


def bswap_32(value: int) -> int:
    """Swap bytes in 32-bit value."""
    return (
        ((value << 24) & 0xff000000) |
        ((value << 8) & 0xff0000) |
        ((value >> 8) & 0xff00) |
        ((value >> 24) & 0xff)
    )


def swab32(value: int) -> int:
    """Swap 32-bit value (alias for bswap_32)."""
    return bswap_32(value)


# ============================================================================
# Hex string to byte array conversion
# ============================================================================

def hex_char_to_int(ch: str) -> int:
    """Convert single hex character to integer."""
    code = ord(ch)
    r = (code - 55) if code > 57 else (code - 48)
    return r & 0x0F


def to_byte_array(hex_str: str) -> bytes:
    """
    Convert hex string to byte array.

    Args:
        hex_str: Hexadecimal string (e.g., "deadbeef")

    Returns:
        Byte array representation
    """
    # Remove any whitespace
    hex_str = hex_str.replace(" ", "").replace("\n", "")

    # Use Python's built-in conversion for simplicity
    if len(hex_str) % 2 != 0:
        # Odd length - pad with leading zero
        hex_str = "0" + hex_str

    return bytes.fromhex(hex_str)


def swap_endian_words(hex_words: str) -> bytes:
    """
    Swap endianness of 4-byte words in hex string.

    Args:
        hex_words: Hex string with 4-byte word alignment

    Returns:
        Byte array with swapped endianness per word
    """
    if len(hex_words) % 8 != 0:
        raise ValueError("Must be 4-byte word aligned")

    result = bytearray()
    for i in range(0, len(hex_words), 8):
        word_hex = hex_words[i:i+8]
        # Parse as big-endian, write as little-endian
        word_bytes = bytes.fromhex(word_hex)
        result.extend(word_bytes[::-1])  # Reverse the 4 bytes

    return bytes(result)


def reverse_bytes(data: bytes) -> bytes:
    """Reverse byte order of data."""
    return data[::-1]


# ============================================================================
# Difficulty calculations (ported from NerdMiner_v2)
# ============================================================================

# Bitcoin difficulty 1 target value
TRUEDIFFONE = 26959535291011309493156476344723991336010898738574164086137773096960.0


def le256todouble(target: bytes) -> float:
    """
    Convert little-endian 256-bit value to double.

    This matches NerdMiner_v2's le256todouble function for accurate
    difficulty calculation.

    Args:
        target: 32-byte target value (little-endian)

    Returns:
        Floating-point representation of target
    """
    if len(target) != 32:
        raise ValueError("Target must be 32 bytes")

    # Extract 64-bit chunks (little-endian)
    data64_0 = struct.unpack("<Q", target[0:8])[0]
    data64_1 = struct.unpack("<Q", target[8:16])[0]
    data64_2 = struct.unpack("<Q", target[16:24])[0]
    data64_3 = struct.unpack("<Q", target[24:32])[0]

    # Calculate weighted sum
    dcut64 = data64_3 * 6277101735386680763835789423207666416102355444464034512896.0
    dcut64 += data64_2 * 340282366920938463463374607431768211456.0
    dcut64 += data64_1 * 18446744073709551616.0
    dcut64 += data64_0

    return dcut64


def diff_from_target(target: bytes) -> float:
    """
    Calculate difficulty from target (matches NerdMiner_v2 implementation).

    Args:
        target: 32-byte target value (little-endian)

    Returns:
        Difficulty value
    """
    dcut64 = le256todouble(target)
    if dcut64 == 0.0:
        dcut64 = 1.0
    return TRUEDIFFONE / dcut64


def diff_from_hash(hash_bytes: bytes) -> float:
    """
    Calculate difficulty from hash result.
    Interprets hash as little-endian 256-bit integer.

    Args:
        hash_bytes: 32-byte hash (little-endian)

    Returns:
        Difficulty represented by hash
    """
    return diff_from_target(hash_bytes)


# ============================================================================
# Hash validation
# ============================================================================

def is_sha256_valid(sha256_hash: bytes) -> bool:
    """
    Check if SHA256 hash is non-zero.

    Args:
        sha256_hash: 32-byte hash value

    Returns:
        True if hash contains at least one non-zero byte
    """
    if len(sha256_hash) != 32:
        return False

    # Check if all 32 bytes are zero
    for i in range(32):
        if sha256_hash[i] != 0:
            return True
    return False


def check_valid(hash_result: bytes, target: bytes) -> bool:
    """
    Check if hash is valid (hash <= target).

    Both values are interpreted as little-endian 256-bit integers.

    Args:
        hash_result: 32-byte hash (little-endian)
        target: 32-byte target (little-endian)

    Returns:
        True if hash <= target
    """
    if len(hash_result) != 32 or len(target) != 32:
        return False

    # Compare bytes from most significant to least (reverse order for little-endian)
    for i in range(31, -1, -1):
        if hash_result[i] > target[i]:
            return False
        elif hash_result[i] < target[i]:
            return True

    # Equal
    return True


# ============================================================================
# Extranonce2 generation
# ============================================================================

def get_random_extranonce2(extranonce2_size: int) -> str:
    """
    Generate random extranonce2 value.

    Args:
        extranonce2_size: Size in bytes (typically 2, 4, or 8)

    Returns:
        Hex string of specified length
    """
    import random

    # Generate random bytes
    random_value = random.randint(0, (1 << (extranonce2_size * 8)) - 1)

    # Format as hex string with proper padding
    return f"{random_value:0{extranonce2_size * 2}x}"


def get_next_extranonce2(current_extranonce2: str, extranonce2_size: int) -> str:
    """
    Increment extranonce2 linearly.

    Args:
        current_extranonce2: Current hex string
        extranonce2_size: Size in bytes

    Returns:
        Next hex string (current + 1)
    """
    # Parse as integer, increment, format back
    current_value = int(current_extranonce2, 16) if current_extranonce2 else 0
    next_value = (current_value + 1) & ((1 << (extranonce2_size * 8)) - 1)

    return f"{next_value:0{extranonce2_size * 2}x}"


# ============================================================================
# CRC32 implementation (matches NerdMiner_v2 NVS validation)
# ============================================================================

# CRC32 lookup table (same as in utils.cpp)
CRC32_TABLE = [
    0x00000000, 0x77073096, 0xEE0E612C, 0x990951BA,
    0x076DC419, 0x706AF48F, 0xE963A535, 0x9E6495A3,
    0x0EDB8832, 0x79DCB8A4, 0xE0D5E91E, 0x97D2D988,
    0x09B64C2B, 0x7EB17CBD, 0xE7B82D07, 0x90BF1D91,
    0x1DB71064, 0x6AB020F2, 0xF3B97148, 0x84BE41DE,
    0x1ADAD47D, 0x6DDDE4EB, 0xF4D4B551, 0x83D385C7,
    0x136C9856, 0x646BA8C0, 0xFD62F97A, 0x8A65C9EC,
    0x14015C4F, 0x63066CD9, 0xFA0F3D63, 0x8D080DF5,
    0x3B6E20C8, 0x4C69105E, 0xD56041E4, 0xA2677172,
    0x3C03E4D1, 0x4B04D447, 0xD20D85FD, 0xA50AB56B,
    0x35B5A8FA, 0x42B2986C, 0xDBBBC9D6, 0xACBCF940,
    0x32D86CE3, 0x45DF5C75, 0xDCD60DCF, 0xABD13D59,
    0x26D930AC, 0x51DE003A, 0xC8D75180, 0xBFD06116,
    0x21B4F4B5, 0x56B3C423, 0xCFBA9599, 0xB8BDA50F,
    0x2802B89E, 0x5F058808, 0xC60CD9B2, 0xB10BE924,
    0x2F6F7C87, 0x58684C11, 0xC1611DAB, 0xB6662D3D,
    0x76DC4190, 0x01DB7106, 0x98D220BC, 0xEFD5102A,
    0x71B18589, 0x06B6B51F, 0x9FBFE4A5, 0xE8B8D433,
    0x7807C9A2, 0x0F00F934, 0x9609A88E, 0xE10E9818,
    0x7F6A0DBB, 0x086D3D2D, 0x91646C97, 0xE6635C01,
    0x6B6B51F4, 0x1C6C6162, 0x856530D8, 0xF262004E,
    0x6C0695ED, 0x1B01A57B, 0x8208F4C1, 0xF50FC457,
    0x65B0D9C6, 0x12B7E950, 0x8BBEB8EA, 0xFCB9887C,
    0x62DD1DDF, 0x15DA2D49, 0x8CD37CF3, 0xFBD44C65,
    0x4DB26158, 0x3AB551CE, 0xA3BC0074, 0xD4BB30E2,
    0x4ADFA541, 0x3DD895D7, 0xA4D1C46D, 0xD3D6F4FB,
    0x4369E96A, 0x346ED9FC, 0xAD678846, 0xDA60B8D0,
    0x44042D73, 0x33031DE5, 0xAA0A4C5F, 0xDD0D7CC9,
    0x5005713C, 0x270241AA, 0xBE0B1010, 0xC90C2086,
    0x5768B525, 0x206F85B3, 0xB966D409, 0xCE61E49F,
    0x5EDEF90E, 0x29D9C998, 0xB0D09822, 0xC7D7A8B4,
    0x59B33D17, 0x2EB40D81, 0xB7BD5C3B, 0xC0BA6CAD,
    0xEDB88320, 0x9ABFB3B6, 0x03B6E20C, 0x74B1D29A,
    0xEAD54739, 0x9DD277AF, 0x04DB2615, 0x73DC1683,
    0xE3630B12, 0x94643B84, 0x0D6D6A3E, 0x7A6A5AA8,
    0xE40ECF0B, 0x9309FF9D, 0x0A00AE27, 0x7D079EB1,
    0xF00F9344, 0x8708A3D2, 0x1E01F268, 0x6906C2FE,
    0xF762575D, 0x806567CB, 0x196C3671, 0x6E6B06E7,
    0xFED41B76, 0x89D32BE0, 0x10DA7A5A, 0x67DD4ACC,
    0xF9B9DF6F, 0x8EBEEFF9, 0x17B7BE43, 0x60B08ED5,
    0xD6D6A3E8, 0xA1D1937E, 0x38D8C2C4, 0x4FDFF252,
    0xD1BB67F1, 0xA6BC5767, 0x3FB506DD, 0x48B2364B,
    0xD80D2BDA, 0xAF0A1B4C, 0x36034AF6, 0x41047A60,
    0xDF60EFC3, 0xA867DF55, 0x316E8EEF, 0x4669BE79,
    0xCB61B38C, 0xBC66831A, 0x256FD2A0, 0x5268E236,
    0xCC0C7795, 0xBB0B4703, 0x220216B9, 0x5505262F,
    0xC5BA3BBE, 0xB2BD0B28, 0x2BB45A92, 0x5CB36A04,
    0xC2D7FFA7, 0xB5D0CF31, 0x2CD99E8B, 0x5BDEAE1D,
    0x9B64C2B0, 0xEC63F226, 0x756AA39C, 0x026D930A,
    0x9C0906A9, 0xEB0E363F, 0x72076785, 0x05005713,
    0x95BF4A82, 0xE2B87A14, 0x7BB12BAE, 0x0CB61B38,
    0x92D28E9B, 0xE5D5BE0D, 0x7CDCEFB7, 0x0BDBDF21,
    0x86D3D2D4, 0xF1D4E242, 0x68DDB3F8, 0x1FDA836E,
    0x81BE16CD, 0xF6B9265B, 0x6FB077E1, 0x18B74777,
    0x88085AE6, 0xFF0F6A70, 0x66063BCA, 0x11010B5C,
    0x8F659EFF, 0xF862AE69, 0x616BFFD3, 0x166CCF45,
    0xA00AE278, 0xD70DD2EE, 0x4E048354, 0x3903B3C2,
    0xA7672661, 0xD06016F7, 0x4969474D, 0x3E6E77DB,
    0xAED16A4A, 0xD9D65ADC, 0x40DF0B66, 0x37D83BF0,
    0xA9BCAE53, 0xDEBB9EC5, 0x47B2CF7F, 0x30B5FFE9,
    0xBDBDF21C, 0xCABAC28A, 0x53B39330, 0x24B4A3A6,
    0xBAD03605, 0xCDD70693, 0x54DE5729, 0x23D967BF,
    0xB3667A2E, 0xC4614AB8, 0x5D681B02, 0x2A6F2B94,
    0xB40BBE37, 0xC30C8EA1, 0x5A05DF1B, 0x2D02EF8D,
]


def crc32_reset() -> int:
    """Initialize CRC32 calculation."""
    return 0xFFFFFFFF


def crc32_add(crc32: int, data: bytes) -> int:
    """
    Add data to CRC32 calculation.

    Args:
        crc32: Current CRC32 value
        data: Data bytes to add

    Returns:
        Updated CRC32 value
    """
    for byte in data:
        crc32 = (crc32 >> 8) ^ CRC32_TABLE[(crc32 ^ byte) & 0xFF]
    return crc32


def crc32_finish(crc32: int) -> int:
    """
    Finalize CRC32 calculation.

    Args:
        crc32: Current CRC32 value

    Returns:
        Final CRC32 checksum
    """
    return crc32 ^ 0xFFFFFFFF


def calculate_crc32(data: bytes) -> int:
    """
    Calculate CRC32 checksum for data.

    Args:
        data: Input bytes

    Returns:
        CRC32 checksum
    """
    crc = crc32_reset()
    crc = crc32_add(crc, data)
    return crc32_finish(crc)


# ============================================================================
# String formatting with SI unit suffixes
# ============================================================================

def suffix_string(val: float, sigdigits: int = 0) -> str:
    """
    Convert value to string with SI unit suffix (K, M, G, T, P, E).

    Matches NerdMiner_v2's suffix_string function for displaying
    hashrates and difficulties.

    Args:
        val: Numeric value
        sigdigits: Number of significant digits (0 for auto)

    Returns:
        Formatted string with suffix (e.g., "1.23M", "456.78G")
    """
    MIN_DIFF = 0.001

    if val >= 1e18:  # Exa
        dval = val / 1e15 / 1000
        suffix = "E"
        dval = min(dval, 999.99)
    elif val >= 1e15:  # Peta
        dval = val / 1e12 / 1000
        suffix = "P"
    elif val >= 1e12:  # Tera
        dval = val / 1e9 / 1000
        suffix = "T"
    elif val >= 1e9:  # Giga
        dval = val / 1e6 / 1000
        suffix = "G"
    elif val >= 1e6:  # Mega
        dval = val / 1e3 / 1000
        suffix = "M"
    elif val >= 1e3:  # Kilo
        dval = val / 1000
        suffix = "K"
    else:
        dval = val
        suffix = ""
        if dval < MIN_DIFF:
            dval = 0.0

    # Determine decimal places
    if suffix:
        if dval > 99.999:
            frac = 1
        elif dval > 9.999:
            frac = 2
        else:
            frac = 3
    else:
        if dval > 99.999:
            frac = 2
        elif dval > 9.999:
            frac = 3
        else:
            frac = 4

    if sigdigits == 0:
        # Auto formatting
        return f"{dval:.{frac}f}{suffix}"
    else:
        # Fixed significant digits
        import math
        ndigits = sigdigits - 1 - \
            (math.floor(math.log10(dval)) if dval > 0 else 0)
        ndigits = max(0, int(ndigits))
        return f"{dval:.{ndigits}f}{suffix}"


# ============================================================================
# Double SHA-256 (convenience wrapper)
# ============================================================================

def double_sha256(data: bytes) -> bytes:
    """Compute double SHA-256 hash (SHA256(SHA256(data)))."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()
