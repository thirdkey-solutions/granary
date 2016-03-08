#! /usr/bin/env python
"""
"""

import sys
import pytest
import mock
import logging
import itertools
from binascii import hexlify, unhexlify

from granary.seed import Seed
import granary.seedlib as seedlib
import granary.ssss_wrapper as ssss_wrapper
from granary import electrum_v1_mnemonic

logging.basicConfig(level=logging.DEBUG)

seed1 = Seed()
seed2 = Seed()

SEED1_HEX = "1c63b7708849a5050cae9e4648c0a3ba73c9edf3e767a1a5be40280657221392"
SEED1_BIN = unhexlify(SEED1_HEX)
SEED1_FINGERPRINT = "80D246"
SEED1_MNEMONIC = "broccoli buffalo switch awesome olympic little crawl stable edge ecology cigar insane develop want sort undo payment combine mosquito exotic grace much exact execute"
SEED1_HD_ROOT = "xprv9s21ZrQH143K3ZbAyNipHBfPmvYCA53tpu87dyMgb4etKBJMCZHQT3rTYKnxY1q87LSNwBcJnzoTMyJaoTBWcBsZz1GgaQD84WqBEPyJ2ZS"

STRETCH_PASSWORD = "test"

SEED1_STRETCHED_HEX = "2e5780223c84c7da62801c17fe957439bd138a8d2c2e55a491efc0710abbe454"
SEED1_STRETCHED_BIN = unhexlify(SEED1_STRETCHED_HEX)

SEED1_BIN_CORRECT_HEX_SHARES = ['742bbfb654a8a7f49f49e28f2ab5d6296f9708b45899d330e331397793e9b126', 'bff7b85bac16476514e8dff9fcc4984e398e982e856e4e68ccdd7796a19f9637', '06bc4500fb83e7159277cb2bb1145d930b8617a731c33aa0d6794dc9b04d88d9', '284fb7805d6b864603aaa5145026048095bdb91b3e8174d89305ea54c573dc2e', '91044adb0afe26368535b1c61df6c15da7b536928a2c001089a1d00bd4a1c2c0']
SEED1_BIN_CORRECT_BIN_SHARES = [unhexlify(s) for s in SEED1_BIN_CORRECT_HEX_SHARES]
SEED1_BIN_INCORRECT_HEX_SHARES = SEED1_BIN_CORRECT_HEX_SHARES
SEED1_BIN_INCORRECT_HEX_SHARES[0] = 'ff' * 32
SEED1_BIN_INCORRECT_BIN_SHARES = [unhexlify(s) for s in SEED1_BIN_INCORRECT_HEX_SHARES]

SEED2_HEX = "6c0a51772406d63ab43e0d333541ce0378bdd86a891dfc2d432b94ccf5ed0d64"
SEED2_BIN = unhexlify(SEED2_HEX)
SEED2_FINGERPRINT = "0C5D0A"
SEED2_MNEMONIC = "hire family fruit elite hope bubble special script creek present inform alone mesh umbrella pretty casual wire head slab civil soon walk culture matter"
SEED2_ENCRYPTED = unhexlify("8175cd865fa8fe510a83d25aa1eca15ae74a53204dda31332bf5df6a56841c74")
SEED2_HD_ROOT = "xprv9s21ZrQH143K35CcAfAhex5VqGZrLRqcWS89PeQASWPvKipN4p3QB4VV56DMZLCwH5y7t2Mtqs66GJME1gB5ZVekon7rHsR5CLutfvosHSw"


# Test seedlib
def test_constants():
    assert seedlib.PBKDF2_ROUNDS == 200000
    assert seedlib.quorum_shares == 2
    assert seedlib.total_shares == 5

def test_fingerprint():
    assert(seedlib.fingerprint(SEED1_BIN) == SEED1_FINGERPRINT)
    assert(seedlib.fingerprint(SEED2_BIN) == SEED2_FINGERPRINT)

    assert(seedlib.fingerprint('\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00') == "EC37BB")
    assert(seedlib.fingerprint('\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff') == "9C4051")
    assert(seedlib.fingerprint("") == "52B855")


def test_bip39_mnemonic_decode_12_words():
    assert(seedlib.mnemonic_decode("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about") == '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')


def test_bip39_mnemonic_decode_24_words():
    assert(seedlib.mnemonic_decode("legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title") == '\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f\x7f')


def test_bip39_mnemonic_decode_exception_length():
    with pytest.raises(Exception) as exc:
        seedlib.mnemonic_decode("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    assert "Unexpected length of mnemonic sentence" in exc.value


def test_bip39_mnemonic_decode_exception_word():
    with pytest.raises(Exception) as exc:
        seedlib.mnemonic_decode("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon bbq about")
    assert "Unable to map mnemonic word" in exc.value


def test_bip39_mnemonic_decode_exception_checksum():
    with pytest.raises(Exception) as exc:
        seedlib.mnemonic_decode("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon zoo")
    assert "Mnemonic sentence does not match checksum" in exc.value


def test_electrumv1_mnemonic_encode():
    mnemonic = electrum_v1_mnemonic.mn_encode(SEED1_HEX[:32])
    print mnemonic
    assert mnemonic == ""

def test_ssss_combine_unindexed_exception():
    if not ssss_wrapper.ssss_installed():
        return True

    with pytest.raises(Exception) as exc:
        ssss_wrapper.ssss_combine_unindexed(SEED1_BIN_INCORRECT_BIN_SHARES[:2], SEED1_FINGERPRINT)
    assert "Failed to reconstruct key from shares!" in exc.value


def test_ssss_combine_unindexed_permutation():
    if not ssss_wrapper.ssss_installed():
        return True

    for permutation in itertools.permutations(SEED1_BIN_CORRECT_BIN_SHARES, seedlib.total_shares):
        reconstructed_key = ssss_wrapper.ssss_combine_unindexed(permutation, SEED1_FINGERPRINT)
        assert(reconstructed_key == SEED1_BIN)


def test_ssss_split():
    if not ssss_wrapper.ssss_installed():
        return True

    unindexed_binary_shares = ssss_wrapper.ssss_split(SEED1_BIN)
    print [hexlify(s) for s in unindexed_binary_shares]
    assert(len(unindexed_binary_shares) == seedlib.total_shares)
    reconstructed_key = ssss_wrapper.ssss_combine_unindexed(unindexed_binary_shares, SEED1_FINGERPRINT)
    assert(reconstructed_key == SEED1_BIN)


def test_stretching():
    print "Testing key stretching, this may take a while"
    stretched_key = seedlib.stretched_key(SEED1_BIN, STRETCH_PASSWORD)
    assert(stretched_key == SEED1_STRETCHED_BIN)


def test_encryption():
    ciphertext = seedlib.encrypt(SEED2_BIN, SEED1_STRETCHED_BIN)
    assert(ciphertext == SEED2_ENCRYPTED)


def test_decryption():
    plaintext = seedlib.decrypt(SEED2_ENCRYPTED, SEED2_FINGERPRINT, SEED1_STRETCHED_BIN)
    assert(plaintext == SEED2_BIN)


def test_filename_regex():
    filename = seedlib.master_filename_template % SEED2_FINGERPRINT
    extract_fingerprint = seedlib.regex_master_filename_fingerprint.search(filename).groupdict()['fingerprint']
    assert extract_fingerprint == SEED2_FINGERPRINT
    filename = seedlib.seed_filename_template % SEED2_FINGERPRINT
    extract_fingerprint = seedlib.regex_seed_filename_fingerprint.search(filename).groupdict()['fingerprint']
    assert extract_fingerprint == SEED2_FINGERPRINT

#
# test high-level Seed class
#

def test_seed_hex_init():
    seed1.from_hex(SEED1_HEX)
    seed2.from_hex(SEED2_HEX)
    hex_seed1 = seed1.as_hex()
    hex_seed2 = seed2.as_hex()
    assert hex_seed1 == SEED1_HEX
    assert hex_seed2 == SEED2_HEX

def test_seed_fingerprint():
    seed1.from_hex(SEED1_HEX)
    seed2.from_hex(SEED2_HEX)
    assert seed1.fingerprint() == SEED1_FINGERPRINT
    assert seed2.fingerprint() == SEED2_FINGERPRINT
    seed1.from_hex(SEED2_HEX)
    assert seed1.fingerprint() != SEED1_FINGERPRINT

def test_seed_mnemonic():
    seed1.from_hex(SEED1_HEX)
    seed2.from_hex(SEED2_HEX)
    mnemonic1 = seed1.as_mnemonic()
    mnemonic2 = seed2.as_mnemonic()
    print mnemonic1
    print mnemonic2
    assert mnemonic1 == SEED1_MNEMONIC
    assert mnemonic2 == SEED2_MNEMONIC
    seed1.from_mnemonic(mnemonic1)
    seed2.from_mnemonic(mnemonic2)
    assert seed1.fingerprint() == SEED1_FINGERPRINT
    assert seed2.fingerprint() == SEED2_FINGERPRINT

def test_seed_bin_init():
    SEED1_BIN = unhexlify(SEED1_HEX)
    SEED2_BIN = unhexlify(SEED2_HEX)
    seed1.from_bin(SEED1_BIN)
    seed2.from_bin(SEED2_BIN)
    assert seed1.fingerprint() == SEED1_FINGERPRINT
    assert seed2.fingerprint() == SEED2_FINGERPRINT

def test_seed_stretch():
    newseed = seed1.stretched(STRETCH_PASSWORD)
    assert newseed.as_hex() == SEED1_STRETCHED_HEX

def test_seed_as_HD_root():
    seed1.from_hex(SEED1_HEX)
    seed2.from_hex(SEED2_HEX)
    assert seed1.as_HD_root() == SEED1_HD_ROOT
    assert seed2.as_HD_root() == SEED2_HD_ROOT

def test_seed_BIP39_testvector():
    seed1.from_hex("3e141609b97933b66a060dcddc71fad1d91677db872031e85f4c015c5e7e8982")
    assert seed1.as_HD_root() == "xprv9s21ZrQH143K31xupMrCAi6gmQxGTZkY1W9TFaXLVenbdZ84jaYU82Gz7SkjgpV9oidDnYJu1W9SZ3nH35b6eeQirsi2dNmH37d215jjp9s"


if __name__ == '__main__':
    pytest.main('-v')
