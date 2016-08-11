import seedlib
import string
import json
from mnemonic import Mnemonic
from binascii import hexlify, unhexlify
import bitcoin

# class Granary():
#     pass

class Seed():
      
    def __init__(self):
        self._bin_seed = None
        self._fingerprint = None
        self._bip32_xpriv = None
        
    def __nonzero__(self):
        return bool(self._bin_seed)
        
    def __repr__(self):
        return "< Seed: %s >" % self.fingerprint() if self else "< Seed: empty >"
        
    def bin_seed(self):
        return self._bin_seed
        
    def fingerprint(self):
        if not self._bin_seed:
            return None
        self._fingerprint = seedlib.fingerprint(self._bin_seed) 
        return self._fingerprint
        
    def from_random(self):
        self._bin_seed = seedlib.random_key()
        
    def from_bin(self, bin_seed):
        assert(len(bin_seed) == 32)
        self._bin_seed = bin_seed
             
    def from_hex(self, hex_seed):
        assert(set(hex_seed) <= set(string.hexdigits))
        assert(len(hex_seed) == 64)
        self._bin_seed = unhexlify(hex_seed)
        
    def as_hex(self):
        return hexlify(self._bin_seed) if self._bin_seed else None
        
    def from_mnemonic(self, mnemonic):
        self._bin_seed = seedlib.mnemonic_decode(mnemonic)
        
    def as_mnemonic(self):
        return seedlib.mnemonic_encode(self._bin_seed) if self._bin_seed else None

    def stretched(self, passphrase):
        # stretch key
        newseed = Seed()
        newseed.from_bin(seedlib.stretched_key(self._bin_seed, passphrase))
        return newseed
        
    # mnemonic seed -> BIP39 -> BIP32 xpriv
    def as_HD_root(self):
        # BIP39 compatible derivation from seed mnemonic without passphrase
        master_seed = seedlib.mnemonic.to_seed(self.as_mnemonic())
        # Master key pair for BIP32
        master_xpriv = bitcoin.bip32_master_key(master_seed)
        return master_xpriv

          
