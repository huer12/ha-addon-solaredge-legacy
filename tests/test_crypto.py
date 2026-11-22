import os

from app.crypto import SEDecrypt, calc_crc
from helpers import encrypt


def test_crc_of_empty_data_is_init_value():
    assert calc_crc(b"") == 0x5A5A


def test_crc_changes_with_single_bit_flip():
    assert calc_crc(b"\x00\x01\x02") != calc_crc(b"\x00\x01\x03")


def test_decrypt_reverses_encrypt_over_multiple_keystream_blocks():
    # Arrange
    key, msg0503 = os.urandom(16), os.urandom(34)
    plain = os.urandom(200)

    # Act
    decrypted = SEDecrypt(key, msg0503).decrypt(encrypt(key, msg0503, plain))

    # Assert
    assert decrypted == plain


def test_decrypt_with_wrong_session_key_gives_garbage():
    key, msg0503 = os.urandom(16), os.urandom(34)
    plain = os.urandom(64)

    decrypted = SEDecrypt(key, os.urandom(34)).decrypt(encrypt(key, msg0503, plain))

    assert decrypted != plain
