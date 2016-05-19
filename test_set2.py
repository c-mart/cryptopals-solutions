import set2
import pytest
import base64
import random


def test_pkcs7_pad():
    assert set2.pkcs7_pad(b"YELLOW SUBMARINE", 20) == b"YELLOW SUBMARINE\x04\x04\x04\x04", \
        "Should have four bytes of padding"


def test_pkcs7_pad_no_padding():
    assert set2.pkcs7_pad(b"YELLOW SUBMARINE", 16) == b"YELLOW SUBMARINE", \
        "Should have no padding because input is same length as block"


def test_pkcs7_pad_max_padding():
    assert set2.pkcs7_pad(b"YELLOW SUBMARINES", 16) == \
           b"YELLOW SUBMARINES\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f", \
        "Should have 15 bytes of padding"


def test_pkcs7_pad_invalid_block_size():
    with pytest.raises(ValueError):
        set2.pkcs7_pad(b"YELLOW SUBMARINE", 0)
    with pytest.raises(ValueError):
        set2.pkcs7_pad(b"YELLOW SUBMARINE", -5)
    with pytest.raises(ValueError):
        set2.pkcs7_pad(b"YELLOW SUBMARINE", 14.3)


def test_bytes_to_padded_blocks():
    text = b"The quick brown fox jumps over the lazy dog."
    block_size = 13
    expected_output = [b'The quick bro',
                       b'wn fox jumps ',
                       b'over the lazy',
                       b' dog.\x08\x08\x08\x08\x08\x08\x08\x08']
    assert set2.bytes_to_padded_blocks(text, block_size) == expected_output, \
        "Should return list of blocks with last block padded to block_size"


def test_encrypt_decrypt_aes_cbc_mode():
    plaintext = b"In CBC mode, each ciphertext block is added to the next plaintext " + \
                b"block before the next call to the cipher core."
    key = b"chickens fingers"
    iv = b"honey mustard ok"
    ciphertext = set2.encrypt_aes_cbc_mode(plaintext, key, iv)
    assert set2.decrypt_aes_cbc_mode(ciphertext, key, iv) == plaintext


def test_decrypt_aes_cbc_mode():
    with open("set2_challenge10_ciphertext", mode='r') as file:
        ciphertext_b64 = file.read()
    ciphertext_bytes = base64.b64decode(ciphertext_b64)
    plaintext = set2.decrypt_aes_cbc_mode(ciphertext_bytes, b'YELLOW SUBMARINE', b'\x00' * 16)
    assert b"I'm back and I'm ringin' the bell" in plaintext, \
        "Beginning of plaintext not decrypted"
    assert b"'Cause why the freaks are jockin' like Crazy Glue" in plaintext, \
        "Middle of plaintext not decrypted"


def test_blackbox_encrypt_ecb_or_cbc_oracle_deterministic():
    for i in range(10):
        # Use deterministic randomness
        random.seed(0)
        assert set2.detect_oracle_ecb_or_cbc(set2.encrypt_ecb_or_cbc_oracle)[0] == 'CBC'
    for i in range(10):
        random.seed(1)
        assert set2.detect_oracle_ecb_or_cbc(set2.encrypt_ecb_or_cbc_oracle)[0] == 'ECB'


def test_blackbox_encrypt_ecb_or_cbc_oracle_random():
    results = list()
    for i in range(100):
        results.append(set2.detect_oracle_ecb_or_cbc(set2.encrypt_ecb_or_cbc_oracle)[0])
    assert 30 < results.count("ECB") < 70, "ECB should be used about half the time"
    assert 30 < results.count("CBC") < 70, "CBC should be used about half the time"


def test_detect_oracle_block_size():
    assert set2.detect_oracle_block_size(set2.byte_at_time_ecb_oracle) == 16, \
        "Block size of byte_at_time_ecb_oracle() not detected properly"


def test_byte_at_time_ecb_decryption():
    decrypt = set2.byte_at_time_ecb_decryption(set2.byte_at_time_ecb_oracle)
    expected_pt = b"Rollin' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just" + \
                  b" to say hi\nDid you stop? No, I just drove by\n"
    assert decrypt == expected_pt, "Plaintext not decrypted properly"
