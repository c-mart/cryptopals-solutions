import set2
import pytest


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
