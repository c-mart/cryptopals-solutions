import base64
import binascii
import bitstring
import collections
import string
import pprint
from letter_freq import reference_letter_freq_dict
from Crypto.Cipher import AES

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
