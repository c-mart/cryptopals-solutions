import pytest
import set1
import binascii
import base64
import pprint

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


def test_single_byte_xor_cryptanalysis_example():
    ciphertext = binascii.unhexlify('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    key_byte = b'X'
    plaintext = b"Cooking MC's like a pound of bacon"
    assert set1.single_byte_xor_cryptanalysis(ciphertext)[:2] == (plaintext, ord(key_byte))


def test_single_byte_xor_cryptanalysis_many():
    """Tests ability to break single character xor for several plaintexts encrypted with every possible byte"""
    plaintexts = [b'The optional source parameter can be used to initialize the array',
                  b'The quick brown fox jumps over the lazy dog',
                  b'My mind is the place where I make my plans',
                  b'The world is the place where I take my stand']
    for pt in plaintexts:
        for i in range(255):
            key_byte = bytes([i])
            ct = set1.fixed_xor(pt, key_byte * len(pt))
            assert set1.single_byte_xor_cryptanalysis(ct)[:2] == (pt, ord(key_byte))


def test_detect_single_character_xor():
    with open('set1_challenge4_ciphertext.txt') as file_obj:
        assert set1.detect_single_character_xor(file_obj) == b'Now that the party is jumping\n'


def test_repeating_key_xor():
    pt_bytes = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key_bytes = b"ICE"
    desired_ct = binascii.unhexlify(
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
    assert set1.repeating_key_xor(pt_bytes, key_bytes) == desired_ct


def test_bitwise_hamming_distance():
    assert set1.bitwise_hamming_distance(b'this is a test', b'wokka wokka!!!') == 37, "Invalid bitwise hamming distance"


def test_bitwise_hamming_distance_same_inputs():
    assert set1.bitwise_hamming_distance(b'this is another test', b'this is another test') == 0,\
        "Invalid bitwise hamming distance"


def test_get_repeating_xor_key_size_likelihoods_1():
    ct_bytes = base64.b64decode(
        '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272'
        'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f')
    test_likelihoods = set1.get_repeating_xor_key_size_likelihoods(ct_bytes)
    most_likely_key_sizes = sorted(test_likelihoods, key=test_likelihoods.get)
    assert min(most_likely_key_sizes[:3]) == 3, \
        "3 should be the smallest of the 3 most likely key sizes scored by hamming distance"

    # Here we use the heuristic:
    #     "True key size is probably the smallest of the 3 most likely key sizes according to bitwise hamming distance."
    # Sometimes this works and sometimes it does not.
    # There must be a better way to detect the real key size, e.g. by looking for the repeating multiple of a number.


def test_get_repeating_xor_key_size_likelihoods_2():
    pt_bytes = b"Where's the kaboom? There was supposed to be an earth-shattering kaboom!"
    key_bytes = b"\x00ghee\xff"  # 6 bytes long
    ct_bytes = set1.repeating_key_xor(pt_bytes, key_bytes)
    test_likelihoods = set1.get_repeating_xor_key_size_likelihoods(ct_bytes)
    most_likely_key_sizes = sorted(test_likelihoods, key=test_likelihoods.get)
    assert min(most_likely_key_sizes[:3]) == 6, \
        "6 should be the smallest of the 3 most likely key sizes scored by hamming distance"


def test_transpose_bytes():
    assert set1.transpose_bytes(b'chicken', 2) == [bytearray(b'cikn'), bytearray(b'hce')]
    assert set1.transpose_bytes(b'oboe ode to robed lobe', 3) == [bytearray(b'oedtrele'),
                                                                  bytearray(b'b eoodo'),
                                                                  bytearray(b'oo  b b')]


"""
def test_break_repeating_key_xor():
    pt = b'The libel pleaded that the pew was erected under a faculty in 1725, and was transferred to Haines in 1816.'
    key = b'\x00\x00\xff'
    test = set1.repeating_key_xor(pt, key)
    print(test)
    print(set1.break_repeating_key_xor(test))
"""

test = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
ciphertext_bytes = binascii.unhexlify(test)
print(ciphertext_bytes)
print(set1.break_repeating_key_xor(ciphertext_bytes))

"""
with open('set1_challenge6_ciphertext.txt') as file:
    ciphertext_text = file.read()
ciphertext_b64 = ciphertext_text.replace('\n', '')
ciphertext_bytes = base64.b64decode(ciphertext_b64)
# MOSTLY works, tends to get the key length wrong
print(break_repeating_key_xor(ciphertext_bytes))
"""

# print(repeating_key_xor(ciphertext_bytes, b'Terminator X: Bring the noise'))