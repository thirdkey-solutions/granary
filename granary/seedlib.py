import os
import time
import random
import logging
import getpass
from binascii import hexlify, unhexlify
import re

import hashlib
from pbkdf2 import PBKDF2
import gnupg

import bitcoin
from mnemonic import Mnemonic
from Crypto.Cipher import Blowfish

import ssss_wrapper

logging.basicConfig(level=logging.ERROR)

mnemonic = Mnemonic('english')
gpg = gnupg.GPG()


PBKDF2_ROUNDS = 200000

gpg_recipients = ["4D39C707","885C379E"]

# 2 of 5
quorum_shares = 2
total_shares = 5

master_filename_template = "master_%s_.txt"
regex_master_filename_fingerprint = re.compile(r"master_(?P<fingerprint>[0-9A-Z]+)_\.txt")

seed_filename_template = "seed_%s_.txt"
regex_seed_filename_fingerprint = re.compile(r"seed_(?P<fingerprint>[0-9A-Z]+)_\.txt")


def mnemonic_encode(binary_key):
    return mnemonic.to_mnemonic(binary_key)


def mnemonic_decode(mnemonic_code):
    mnemonic_code = mnemonic_code.split(' ')
    if len(mnemonic_code) % 3 > 0:
        raise Exception("Unexpected length of mnemonic sentence")
    try:
        idx = map(lambda x: bin(mnemonic.wordlist.index(x))[2:].zfill(11), mnemonic_code)
        b = ''.join(idx)
    except:
        raise Exception("Unable to map mnemonic word")
    l = len(b)
    d = b[:l // 33 * 32]
    h = b[-l // 33:]
    nd = unhexlify(hex(int(d, 2))[2:].rstrip('L').zfill(l // 33 * 8))
    nh = bin(int(hashlib.sha256(nd).hexdigest(), 16))[2:].zfill(256)[:l // 33]
    if (nh==h):
        return nd
    else:
        raise Exception("Mnemonic sentence does not match checksum")


def random_key():
    entropy = ""
    # add local sources of entropy
    entropy += str(os.urandom(32))
    entropy += str(random.randrange(2**256))
    entropy += str(int(time.time() * 1000000))

    # add external entropy
    i = 1
    additional_entropy = getpass.getpass("Enter entropy from source %d " % i)
    while additional_entropy:
        entropy += additional_entropy
        i += 1
        additional_entropy = getpass.getpass("Enter entropy from source %d " % i)

    # stretch entropy to defend (somewhat) against brute force of weak sources
    print "Stretching entropy..."
    key = stretched_key(entropy, str(time.time()))
    return key


def fingerprint(binary_key):
    return hashlib.sha256(binary_key).hexdigest()[-6:].upper()


def split(binary_key):
    shares = ssss_wrapper.ssss_split(binary_key)
    mnemonic_share_list = []
    for share in shares:
        mnemonic_share = mnemonic.to_mnemonic(share)
        mnemonic_share_list.append(mnemonic_share)
    assert(len(mnemonic_share_list) == total_shares)
    return mnemonic_share_list


def stretched_key(master_key, passphrase):
     return PBKDF2(master_key, passphrase, iterations=PBKDF2_ROUNDS).read(32)


def encrypt(plaintext, key):
    crypto = Blowfish.new(key, Blowfish.MODE_ECB)
    ciphertext = crypto.encrypt(plaintext)
    fprint = fingerprint(plaintext)
    recovered_plaintext = decrypt(ciphertext, fprint, key)
    assert (recovered_plaintext == plaintext)
    assert (fprint == fingerprint(recovered_plaintext))
    return ciphertext


def decrypt(ciphertext, expected_fingerprint, key):
    crypto = Blowfish.new(key, Blowfish.MODE_ECB)
    plaintext = crypto.decrypt(ciphertext)
    assert(fingerprint(plaintext) == expected_fingerprint)
    return plaintext


def decode_seed(encrypted_mnemonic, expected_fingerprint, master_crypto_key):
    decoded_mnemonic = mnemonic_decode(encrypted_mnemonic)
    decrypted_seed = decrypt(decoded_mnemonic, expected_fingerprint, master_crypto_key)
    assert(fingerprint(decrypted_seed) == expected_fingerprint)
    return decrypted_seed


def gpg_matching_keys(recipient):
    private_keys = gpg.list_keys(True)
    private_key_ids =[ key_dict['keyid'][-8:] for key_dict in private_keys]
    matching_keys = list(set(private_key_ids).intersection(set(gpg_recipients)))
    return matching_keys

def gpg_decrypt_master(expected_fingerprint):
    master_key_filename = master_filename_template % expected_fingerprint
    if os.path.isfile(master_key_filename):
        logging.info('Found gpg encrypted master key')
    else:
        raise Exception("GPG encrypted master key file not found")
    master_key_file = open(master_key_filename, "r")
    import json
    gpg_data = json.load(master_key_file)
    assert 'pgp' in gpg_data
    gpg_payload = gpg_data['pgp']
    matching_keys = gpg_matching_keys(gpg_recipients)
    if not matching_keys:
        raise Exception("No suitable GPG private keys found for decryption of Master key")
    for recipient in matching_keys:
        logging.info("Found matching GPG private key %s", recipient)
        gpg_passphrase = getpass.getpass("Enter the GPG key passphrase: ")
        decrypted_hex_key = str(gpg.decrypt(gpg_payload, passphrase=gpg_passphrase))
        if fingerprint(unhexlify(decrypted_hex_key)) == expected_fingerprint:
            logging.info("Master key decrypted successfully")
            return unhexlify(decrypted_hex_key)
        else:
            logging.info("Decrypted key didn't match expected fingerprint, trying next GPG key")
    raise Exception("GPG master key decryption failed for all recipients")


def gpg_encrypt_master(hex_key):
    gpg = gnupg.GPG()
    gpg.encoding = 'utf-8'
    return gpg.encrypt(hex_key, gpg_recipients)
