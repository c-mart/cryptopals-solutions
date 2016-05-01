import pytest
import set1
import binascii


def test_hex_to_base64_happy_case():
    some_hex = b'49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    some_base64 = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert set1.hex_to_base64(some_hex) == some_base64


def test_hex_to_base64_sad_case():
    some_not_hex = b'7798374983baacfedce34435k'
    with pytest.raises(TypeError):
        set1.hex_to_base64(some_not_hex)


def test_fixed_xor():
    input_1 = binascii.unhexlify(b'1c0111001f010100061a024b53535009181c')
    input_2 = binascii.unhexlify(b'686974207468652062756c6c277320657965')
    expected_output = binascii.unhexlify(b'746865206b696420646f6e277420706c6179')
    assert set1.fixed_xor(input_1, input_2) == expected_output


def test_single_byte_xor_cryptanalysis_1():
    ciphertext = binascii.unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    key_byte = b'X'
    plaintext = b"Cooking MC's like a pound of bacon"
    assert set1.single_byte_xor_cryptanalysis(ciphertext)[:2] == (plaintext, ord(key_byte))


def test_single_byte_xor_cryptanalysis_2():
    plaintext = b'The optional source parameter can be used to initialize the array'
    key_byte = b'$'
    ciphertext = set1.fixed_xor(plaintext, key_byte * len(plaintext))
    assert set1.single_byte_xor_cryptanalysis(ciphertext)[:2] == (plaintext, ord(key_byte))