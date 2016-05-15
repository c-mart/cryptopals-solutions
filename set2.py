import set1
import os
import random
import base64
import pprint

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


def generate_random_aes_key(len_bytes):
    """Challenge 11
    Generates a random AES key of len_bytes length"""
    return os.urandom(len_bytes)


def _get_random_bytes(length):
    return bytes(random.getrandbits(8) for i in range(length))


def encrypt_ecb_or_cbc_oracle(plaintext):
    """Challenge 11
    - Encrypts plaintext using a random key
    - Pre-pends 5-10 random bytes to plaintext, appends 5-10 bytes to plaintext
    - With 50% probability of each, encrypts plaintext using ECB mode or CBC mode
    - Returns ciphertext

    We're using the random package rather than os.urandom() because it can be seeded for testing
    """

    key = generate_random_aes_key(16)
    plaintext = _get_random_bytes(random.randint(5, 10)) \
                + plaintext \
                + _get_random_bytes(random.randint(5, 10))
    if random.random() < 0.5:
        padded_pt = pkcs7_pad(plaintext, 16)
        return set1.encrypt_aes_ecb_mode(padded_pt, key)
    else:
        iv = _get_random_bytes(16)
        return encrypt_aes_cbc_mode(plaintext, key, iv)


def detect_oracle_ecb_or_cbc(oracle_function):
    """Challenge 11
    Detects whether an oracle function is encrypting using a block cipher in ECB or CBC mode
    oracle_function must accept a plaintext as its single argument
    Returns tuple of either "ECB" or "CBC" and ciphertext
    """
    ciphertext = oracle_function(b'a' * 64)
    # Look for any 16-byte sequence that is repeated
    for sixteen_byte_seq in [ciphertext[i:i+16] for i in range(len(ciphertext) - 16)]:
        if ciphertext.count(sixteen_byte_seq) > 1:
            return "ECB", ciphertext
    return "CBC", ciphertext


# Generate consistent AES key for byte-at-a-time ECB oracle
key_for_byte_at_time_ecb_oracle = generate_random_aes_key(16)


def byte_at_time_ecb_oracle(plaintext):
    """Challenge 12
    - Encrypts given plaintext using a random but consistent key
    - Appends 'secret' base64-encoded string to plaintext before encryption
    - Returns ciphertext

    Using the random package rather than os.urandom() because it can be seeded for testing
    """

    global key_for_byte_at_time_ecb_oracle
    secret_string_b64 = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
                        b'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
                        b'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
                        b'YnkK'
    secret_string_bytes = base64.b64decode(secret_string_b64)
    # padded_combined_pt = pkcs7_pad(plaintext + secret_string_bytes, 16)
    padded_combined_pt = pkcs7_pad(plaintext + secret_string_bytes, 16)
    return set1.encrypt_aes_ecb_mode(padded_combined_pt, key_for_byte_at_time_ecb_oracle)


def detect_oracle_block_size(oracle_function):
    """Detects block size of an oracle function that encrypts using a block cipher.
    oracle_function must accept a plaintext as its single argument.
    """
    pt_len = 1
    ct_size = len(oracle_function(pt_len * b'a'))
    while True:
        pt_len += 1
        new_ct_size = len(oracle_function(pt_len * b'a'))
        if new_ct_size != ct_size:
            return new_ct_size - ct_size
        else:
            ct_size = new_ct_size
            continue


def byte_at_time_ecb_decryption():
    """Challenge 12
    Break an ECB-encrypted block cipher one byte at a time, using byte_at_time_ecb_oracle
    Finds the plaintext
    """
    block_size = detect_oracle_block_size(byte_at_time_ecb_oracle)
    assert detect_oracle_ecb_or_cbc(byte_at_time_ecb_oracle)[0] == "ECB", "Oracle function must encrypt using ECB"
    assert len(byte_at_time_ecb_oracle(b'')) % block_size == 0, \
        "Oracle function must produce a ciphertext whose length is an even multiple of block_size"

    pt_len = len(byte_at_time_ecb_oracle(b''))
    plaintext = b''

    for pt_index in range(pt_len):
        block_start = (pt_index // block_size) * block_size

        pre_pad_0_len = block_size - (pt_index % block_size) - 1
        # Feed the oracle between 0 and (block_size - 1) known bytes, placing the next byte to be decrypted in the last
        # position of its block
        pre_pad = (b'A' * pre_pad_0_len)
        ct_block_unknown_last_byte = byte_at_time_ecb_oracle(pre_pad)[block_start:block_start+block_size]

        # Try encrypting block using all possible values of last byte, store results in dictionary
        ct_block_possible_last_byte_dict = dict()
        for byte_int in range(255):
            byte = bytes([byte_int])
            ct_block = byte_at_time_ecb_oracle(pre_pad + plaintext + byte)[block_start:block_start+block_size]
            ct_block_possible_last_byte_dict[ct_block] = byte
        # The last byte which produces ciphertext block matching ct_block_unknown_last_byte is next byte of plaintext
        try:
            new_pt_byte = ct_block_possible_last_byte_dict[ct_block_unknown_last_byte]
        except KeyError:  # Todo fix this, understand why decryption stops working
            break
        plaintext += new_pt_byte
    return plaintext

print(byte_at_time_ecb_decryption())