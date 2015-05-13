import seedlib
import bitcoin
import getpass
import json

from seed import Seed
from mnemonic import Mnemonic
from binascii import hexlify, unhexlify


def generate_master():
    print "===== Generating TKS Master"
    priv = seedlib.random_key()
    priv_fingerprint = seedlib.fingerprint(priv)
    print "Key fingerprint", priv_fingerprint

    print "===== Splitting TKS Master into mnemonic shares"
    mnemonic_share_list = seedlib.split(priv)
    
    print "===== Printing shares for key fingerprint", priv_fingerprint
    for i in range(5):
        print "\n"
        print i+1,".", mnemonic_share_list[i]
    print "\n"
    
    return priv

    
def gather_master(fingerprint):  
    shares = []
    while (len(shares) < quorum_shares):
        need = quorum_shares - len(shares)
        try:     
            share = str(raw_input("Enter a key share  ("+str(need)+" more needed): "))
            decoded_share = mnemonic_decode(share)
            shares.append(hexlify(decoded_share))
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print e, "... try again"
            
    print "Reconstructing key"
    return recombine_any_two(shares, fingerprint)        


def stretch_master(master_key):
    print "Stretching master key"
    passphrase = getpass.getpass("Type passphrase for master key stretching: ")
    passphrase = seedlib.mnemonic.normalize_string(passphrase)
    print "Password stretching, please wait, may take a while"
    key = seedlib.stretched_key(master_key, passphrase) 
    print "Stretched key fingerprint: ", seedlib.fingerprint(key)
    return key
    

def get_master():
    print "Gathering master key material"
    fingerprint = str(raw_input("Enter the master key fingerprint: "))
    fingerprint = fingerprint.upper()
    print "Fingerprint", fingerprint
    try:
        key = gpg_decrypt_master(fingerprint)
    except Exception as e:
        print e
        print "Unable to open encrypted master key - trying to gather shares"
        key = gather_master(fingerprint)
    return key
    
    
def save_master(master_fingerprint, encrypted_master):
    print "Storing encrypted master"
    keyfilename = seedlib.master_filename_template % master_fingerprint
    keyfile = open(keyfilename,'w')

    key_json = {
        "fingerprint" : master_fingerprint,
        "pgp" : str(encrypted_master),
    }
    key_text = json.dumps(key_json, sort_keys=True, indent=2)
    keyfile.write(key_text)
    keyfile.close
    print key_text
    print "Data saved to ", keyfilename
    
    
def genseed(master_crypto_key):
    if not master_crypto_key:
        raise Exception("genseed requires a master crypto key")
        
    # generate seed
    print "Generating customer seed"
    customer_seed = seedlib.random_key()
    customer_master_priv = bitcoin.bip32_master_key(hexlify(customer_seed))
    customer_fingerprint = seedlib.fingerprint(customer_seed)

    print "Customer key fingerprint:", customer_fingerprint

    print "Encrypting customer seed"
    encrypted_customer_seed = seedlib.encrypt(customer_seed, master_crypto_key)

    print "Creating encrypted mnemonic"
    encrypted_mnemonic = seedlib.mnemonic.to_mnemonic(encrypted_customer_seed)
    print encrypted_mnemonic

    print "Decrypting seed"
    decrypted_seed = seedlib.decode_seed(encrypted_mnemonic, customer_fingerprint, master_crypto_key)

    print "Running validation tests"
    assert(decrypted_seed == customer_seed)
    
    print "Validation tests completed successfully"
    return customer_seed
    
def save_seed(seed, master_crypto_key):
    print "Storing seed"
    keyfilename = seedlib.seed_filename_template % seed.fingerprint()
    keyfile = open(keyfilename,'w')
    
    encrypted_customer_seed = seedlib.encrypt(seed.bin_seed(), master_crypto_key)
    encrypted_mnemonic = seedlib.mnemonic.to_mnemonic(encrypted_customer_seed)
    
    key_json = {
        "fingerprint" : seed.fingerprint(),
        "encrypted_mnemonic" : encrypted_mnemonic,
    }
    key_text = json.dumps(key_json, indent=2, sort_keys=True)
    keyfile.write(key_text)
    keyfile.close
    print key_text
    print "Data saved to ", keyfilename
    
