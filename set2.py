import base64
import binascii
import bitstring
import collections
import string
import pprint
from letter_freq import reference_letter_freq_dict
from Crypto.Cipher import AES
import set1

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
    """Accepts a bytes-like object. Breaks it up into blocks according to block_size. Last block is padded out using
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
