import base64
import binascii
import bitstring
import pprint
import string
from letter_freq import letter_freq_dict

"""
My Python 3 solutions to the Matasano Crypto Challenges, set 1
http://cryptopals.com/sets/1/

To do:
- Separate out testing code into proper tests
- Figure out what's going on with break_repeating_key_xor

"""

"""
print("This is what all the bytes look like!")
for byte in range(256):
    print(bytes([byte]), end=" ")
"""

def hex_to_base64(hex_str):
    """Challenge 1
    Converts hexadecimal string to base64 encoding
    """
    for byte in hex_str:
        if byte not in b"0123456789abcdef":
            raise TypeError("Must provide a hexadecimal string, you may have invalid characters")
    str_bytes = binascii.unhexlify(hex_str)
    str_base64 = base64.b64encode(str_bytes)
    return str_base64


def fixed_xor(bytes1, bytes2):
    """Challenge 2
    XORs two equal-length bytes objects or byte arrays
    """
    assert len(bytes1) == len(bytes2), "You must pass equal-length objects"
    """
    Here we create tuple a, b for each pair of bytes in the inputs. Each byte is represented as an integer.
    We perform a bitwise xor on each pair, then create a list of the XOR'd bytes in sequence.
    Finally, we join all of these bytes together to a new bytes object and return it.
    """
    return bytes().join([bytes([a ^ b]) for a, b in zip(bytes1, bytes2)])


def single_byte_xor_cryptanalysis(ciphertext):
    """Challenge 3
    Performs cryptanalysis on a bytes object (ciphertext) that has been XOR'd against a single byte.
    Returns tuple of most likely plaintext, most likely key byte, and likelihood score.
    """
    plaintexts_dict = {}  # Holds each candidate plaintext and its score
    keys_dict = {}  # Holds each candidate key and its score
    for key_byte in range(256):  # Try decrypting using each byte
        xor_bytes = bytes([key_byte]) * len(ciphertext)  # Expand candidate byte to length of ciphertext
        candidate_plaintext = fixed_xor(ciphertext, xor_bytes)
        # Calculate score of candidate_plaintext using weights from a frequency distribution of letter usage
        score = float(0)
        for pt_byte in candidate_plaintext:
            c = chr(pt_byte)
            if c in string.ascii_lowercase:
                score += letter_freq_dict[c]
            # Upper-case letters count slightly less than lower-case
            if c in string.ascii_uppercase:
                score += letter_freq_dict[c.lower()] * 0.75
        score /= len(ciphertext)  # Normalize score over length of plaintext
        plaintexts_dict[candidate_plaintext] = score
        keys_dict[key_byte] = score
    return max(plaintexts_dict, key=plaintexts_dict.get), \
           max(keys_dict, key=keys_dict.get), \
           max(plaintexts_dict.values())


def detect_single_character_xor(file_obj):
    """Challenge 4
    Performs cryptanalysis on a file object, one of whose lines contains text encrypted using single_byte_xor_cryptanalysis.
    Returns decrypted plaintext of that line.
    """
    line_plaintexts = dict()
    # For each line in file, call single_byte_xor_cryptanalysis to return the most likely plaintext and its score
    for line in file_obj.readlines():
        line = line.strip('\n')  # Get rid of newline at the end of our hexadecimal string
        line_bytes = binascii.unhexlify(line)
        likely_pt, score = single_byte_xor_cryptanalysis(line_bytes)
        line_plaintexts[likely_pt] = score
    return max(line_plaintexts, key=line_plaintexts.get)

# with open('set1_challenge4_ciphertext.txt') as file_obj:
#     print(detect_single_character_xor(file_obj))


def repeating_key_xor(orig_bytes, key_bytes):
    """Challenge 5
    Transforms a bytes object by repeating the key, returns ciphertext
    Key is repeated to match the length of plaintext, then each plaintext byte is XORd with the corresponding key byte.

        PT:  b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
        KEY: b"ICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICEICE"
    """
    expanded_key = bytearray()
    # Repeat the key to fill a bytearray up to the length of the plaintext
    for i in range(len(orig_bytes)):
        expanded_key.append(key_bytes[i % len(key_bytes)])
    return fixed_xor(orig_bytes, expanded_key)

# Tests for repeating key XOR
"""
pt_bytes = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
key_bytes = b"ICE"
print(binascii.hexlify(repeating_key_xor(pt_bytes, key_bytes)))
"""

"""
with open('my_secret.key', 'rb') as my_secret_stuff:
    ct = repeating_key_xor(my_secret_stuff.read(), b'Password1')
    with open('my_encrypted_stuff', 'wb') as my_encrypted_stuff:
        my_encrypted_stuff.write(ct)
"""


def bitwise_hamming_distance(bytes1, bytes2):
    """Returns the bitwise Hamming distance between two bytes objects.
    Based on this definition from https://en.wikipedia.org/wiki/Hamming_distance:
    "For binary strings a and b the Hamming distance is equal to the number of ones (population count) in a XOR b."
    """
    bitwise_xor_byte_integers = [(a ^ b) for a, b in zip(bytes1, bytes2)]
    distance = 0
    for byte in bitwise_xor_byte_integers:
        distance += bin(byte).count('1')  # bin() generates a binary string from a byte
    return distance

assert bitwise_hamming_distance(b'this is a test', b'wokka wokka!!!') == 37, "Invalid bitwise hamming distance"
assert bitwise_hamming_distance(b'this is another test', b'this is another test') == 0, "Invalid bitwise hamming distance"


def get_key_size_likelihoods(ciphertext):
    """Finds likelihood of different key sizes for a repeating-key XOR ciphertext whose key and plaintext are not known
    Does this by computing hamming distance between differently sized blocks
    Returns a dictionary whose keys are possible key/block sizes and values are normalized hamming distance between first two blocks for each key size"""
    key_size_likelihoods = dict()
    for test_key_size in range(1, len(ciphertext) // 4 + 1):  # Only tries key sizes for which we can test four blocks
        # Break up ciphertext into blocks according to key_size
        ct_blocks = [ciphertext[i:i+test_key_size] for i in range(0, len(ciphertext), test_key_size)]
        # Get hamming distances between blocks 0 and 1, and between blocks 2 and 3, normalized over key size
        hdist_normalized_0_1 = bitwise_hamming_distance(ct_blocks[0], ct_blocks[1]) / float(test_key_size)
        hdist_normalized_2_3 = bitwise_hamming_distance(ct_blocks[2], ct_blocks[3]) / float(test_key_size)
        # Take their mean
        mean_hdist_normalized = (hdist_normalized_0_1 + hdist_normalized_2_3) / float(2)
        key_size_likelihoods[test_key_size] = mean_hdist_normalized

        """
        # This code is for visualization and is not strictly needed
        print("Possible block size " + str(test_key_size))
        first_ct_block_bitstring = bitstring.Bits(ct_block_0)
        second_ct_block_bitstring = bitstring.Bits(ct_block_1)
        print("First block:  " + first_ct_block_bitstring.bin)
        print("Second block: " + second_ct_block_bitstring.bin)
        xored_blocks = first_ct_block_bitstring ^ second_ct_block_bitstring
        print("XORed blocks: " + xored_blocks.bin)
        print("Hamming weight of XORed blocks: " + str(xored_blocks.bin.count('1')))
        print("Hamming distance normalized over key size: " + str(hdist_normalized))
        print("Likelihood score: " + str(1 / hdist_normalized))
        print()
        """

    return key_size_likelihoods

# Tests for get_key_size_likelihoods
"""
test_ct_b64 = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
test_ct_bytes = base64.b64decode(test_ct_b64)
test_likelihoods = get_key_size_likelihoods(test_ct_bytes)
most_likely_key_size = sorted(test_likelihoods, key=test_likelihoods.get, reverse=True)[0]
assert most_likely_key_size == 3, "Most likely key size should be 3"
"""

# Sorta works?

"""
test_pt_bytes = b"$^%&* d33, I am hustling. bwenenaoRock n' roll"
test_key_bytes = b"\xeeghee\xff"
test_ct_bytes = repeating_key_xor(test_pt_bytes, test_key_bytes)
test_likelihoods = get_key_size_likelihoods(test_ct_bytes)
pprint.pprint(test_likelihoods)
most_likely_key_sizes = sorted(test_likelihoods, key=test_likelihoods.get)[:3]
print(most_likely_key_sizes)
assert 6 in most_likely_key_sizes, "6 should be one of the most likely key sizes"
"""

"""
test_pt_bytes = b"McNutgets You are a chicken. We are all chickens. SquawK! Let's go lay some eggs."
test_key_bytes = b"34S$$@"
test_ct_bytes = repeating_key_xor(test_pt_bytes, test_key_bytes)
test_likelihoods = get_key_size_likelihoods(test_ct_bytes)
pprint.pprint(test_likelihoods)
most_likely_key_sizes = sorted(test_likelihoods, key=test_likelihoods.get)[:3]
print(most_likely_key_sizes)
"""

def transpose_bytes(input_bytes, block_size):
    """Takes input_bytes of length x and block_size y
    Transposes bytes into groups of length x / y
    where the ith group contains the ith, i+block_size, i+2*block_size, etc. byte
    Returns a list of bytes objects
    """
    bytes_transposed = list()
    for i in range(block_size):
        group = bytearray()
        for j in range(len(input_bytes)):
            if j % block_size == i:
                group.append(input_bytes[j])
        bytes_transposed.append(group)
    return bytes_transposed

assert transpose_bytes(b'chicken', 2) == [bytearray(b'cikn'), bytearray(b'hce')]


def break_repeating_key_xor(ciphertext):
    """Challenge 6 http://cryptopals.com/sets/1/challenges/6/"""

    """
    First, determine the likely size of the key by splitting up ciphertext (bytes object) into equal size blocks
    For various possible block sizes, calculate the hamming distance between the first two blocks
    The key size that results in the smallest hamming distance between blocks is the most likely key
    """

    key_size_likelihoods = get_key_size_likelihoods(ciphertext)
    # Try 5 most likely key sizes
    most_likely_key_sizes = sorted(key_size_likelihoods, key=key_size_likelihoods.get)[:5]
    print("Most likely key sizes: " + str(most_likely_key_sizes))

    for candidate_key_size in most_likely_key_sizes:
        print("Testing key size " + str(candidate_key_size))
        ct_transposed = transpose_bytes(ciphertext, candidate_key_size)

        # Each of these transposed byte groups can be broken using single-character XOR
        most_likely_key = bytearray()
        for i in range(candidate_key_size):
            # print(single_byte_xor_cryptanalysis(ct_transposed[i]))
            most_likely_key_byte = single_byte_xor_cryptanalysis(ct_transposed[i])[1]
            # print("Guessing key byte " + str(most_likely_key_byte))
            most_likely_key.append(most_likely_key_byte)
        print("Most likely key is " + str(most_likely_key))
        print("Guessed plaintext is " + str(repeating_key_xor(ciphertext, most_likely_key)))

# test = repeating_key_xor(b'Ninety and nine concerns occupy my faculties, but a woman is not among them.',
#                   b'\x00\x00\xff')
# print(test)
# print(break_repeating_key_xor(test))

"""
test = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
ciphertext_bytes = base64.b64decode(test)
print(ciphertext_bytes)
print(break_repeating_key_xor(ciphertext_bytes))
"""

"""
with open('set1_challenge6_ciphertext.txt') as file:
    ciphertext_text = file.read()
ciphertext_b64 = ciphertext_text.replace('\n', '')
ciphertext_bytes = base64.b64decode(ciphertext_b64)
# MOSTLY works, tends to get the key length wrong
print(break_repeating_key_xor(ciphertext_bytes))
"""

# print(repeating_key_xor(ciphertext_bytes, b'Terminator X: Bring the noise'))