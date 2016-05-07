import set1
import os
import random

"""
My Python 3 solutions to the Matasano Crypto Challenges, set 2
http://cryptopals.com/sets/2/

"""


def pkcs7_pad(text, block_size):
    """Challenge 9
    Pads text out to an even multiple of block_size bytes using PKCS#7
    """
    if type(block_size) != int or block_size <= 0:
        raise ValueError("Block size must be a positive integer")
    text_bytes = bytes(text)
    if len(text_bytes) % block_size == 0:
        pad_length = 0
    else:
        pad_length = block_size - len(text_bytes) % block_size
    return text_bytes + bytes([pad_length]) * pad_length


def bytes_to_padded_blocks(bytes, block_size):
    """Accepts a bytes-like object. Breaks it up into blocks according to block_size bytes. Last block is padded out using
    PKCS#7. Returns a list of blocks."""
    padded_bytes = pkcs7_pad(bytes, block_size)
    return [padded_bytes[index:index+block_size] for index in range(0, len(bytes), block_size)]


def encrypt_aes_cbc_mode(plaintext, key, iv):
    """Encrypt plaintext with AES in CBC mode, using provided key and iv (initialization vector)"""
    assert len(key) == len(iv), "Key and initialization vector must be same length"
    pt_blocks = bytes_to_padded_blocks(plaintext, len(key))
    ciphertext = b''
    xor_with = iv  # Initially, we XOR plaintext with IV
    # For each block, xor plaintext with xor_with, then encrypt and append to ciphertext.
    # Each successive plaintext block is XORed with the previous ciphertext block before encryption.
    for pt_block in pt_blocks:
        new_ct_block = set1.encrypt_aes_ecb_mode(set1.fixed_xor(pt_block, xor_with), key)
        ciphertext = ciphertext + new_ct_block
        xor_with = new_ct_block
    return ciphertext


def decrypt_aes_cbc_mode(ciphertext, key, iv):
    """Challenge 10
    Decrypt plaintext with AES in CBC mode, using provided key and iv (initialization vector)"""
    assert len(key) == len(iv), "Key and initialization vector must be same length"
    ct_blocks = bytes_to_padded_blocks(ciphertext, len(key))
    plaintext = b''
    xor_with = iv  # Initially, we XOR decrypted ciphertext with IV
    # For each block, decrypt ciphertext, then XOR with xor_with, and append to plaintext.
    # After decryption, each successive decrypted block is XORed with the previous ciphertext block.
    for ct_block in ct_blocks:
        new_pt_block = set1.fixed_xor(xor_with, set1.decrypt_aes_ecb_mode(ct_block, key))
        plaintext = plaintext + new_pt_block
        xor_with = ct_block
    return plaintext


def generate_random_aes_key():
    """Challenge 11
    Generates a random 128-bit AES key"""
    return os.urandom(16)


def _get_random_bytes(length):
    return bytes(random.getrandbits(8) for i in range(length))


def blackbox_encrypt_ecb_or_cbc(plaintext):
    """Challenge 11
    - Encrypts plaintext using a random key
    - Pre-pends 5-10 random bytes to plaintext, appends 5-10 bytes to plaintext
    - With 50% probability of each, encrypts plaintext using ECB mode or CBC mode
    - Returns ciphertext

    We're using the random package rather than os.urandom() because deterministic randomness is testable
    """

    key = generate_random_aes_key()
    plaintext = _get_random_bytes(random.randint(5, 10)) \
                + plaintext \
                + _get_random_bytes(random.randint(5, 10))
    if random.random() < 0.5:
        padded_pt = pkcs7_pad(plaintext, 16)
        return set1.encrypt_aes_ecb_mode(padded_pt, key)
    else:
        iv = _get_random_bytes(16)
        return encrypt_aes_cbc_mode(plaintext, key, iv)


def blackbox_encrypt_ecb_or_cbc_oracle():
    """Challenge 11
    Detects whether blackbox_encrypt_ecb_or_cbc() is encrypting using ECB or CBC mode
    Returns tuple of eithre "ECB" or "CBC" and ciphertext
    """
    ciphertext = blackbox_encrypt_ecb_or_cbc(b'a' * 64)
    # Look for any 16-byte sequence that is repeated
    for sixteen_byte_seq in [ciphertext[i:i+16] for i in range(len(ciphertext) - 16)]:
        if ciphertext.count(sixteen_byte_seq) > 1:
            return "ECB", ciphertext
    return "CBC", ciphertext