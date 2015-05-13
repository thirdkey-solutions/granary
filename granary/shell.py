#! env python
from cmd2 import Cmd
from seed import Seed
import seedlib
import bitcoin
import interactive
from binascii import hexlify, unhexlify
import glob, os


class SeedShell(Cmd):
    
    def do_reset_seeds(self):
        self.master = Seed()
        self.stretched_master = Seed()
        self.seed = Seed()
        self.update_prompt()
        
               
    def update_prompt(self):
        prompt = "granary "
        if self.master:
            prompt += "M-%s" % self.master.fingerprint()
        if self.stretched_master:
            prompt += "# "
        else:
            prompt += "$ "
        self.prompt = prompt
        
        
    def do_seeds(self, arg=None):
        print "Seeds loaded"
        print "-" * 20
        print "Master           : ", self.master.fingerprint() or "None"
        print "Stretched Master : ", self.stretched_master.fingerprint() or "None"
        print "Seed             : ", self.seed.fingerprint() or "None"
        print "-" * 20
        
        
    def do_generate_seed(self, args):
        if not self.master:
            raise Exception("generate_seed: Load or generate a master seed first")
            
        self.do_stretch_master("")
        self.update_prompt()
        self.seed.from_bin(interactive.genseed(self.stretched_master.bin_seed()))
        
        
    def do_load_seed(self, filename):
        if not self.master:
            raise Exception("password: Load the master seed first")
            
        if not filename or not os.path.isfile(filename): 
            raise Exception("load_seed requires a filename")
        
        m = seedlib.regex_seed_filename_fingerprint.search(filename)
        expected_fingerprint = m.groupdict()['fingerprint']
        
        seed_file = open(filename, 'r')
        seed_data = seed_file.read()
        seed_file.close()
        
        expected_fingerprint = seedlib.regex_customer_fingerprint.search(seed_data).groupdict()['fingerprint']
        encrypted_mnemonic = seedlib.regex_customer_seed.search(seed_data).groupdict()['seed']
        expected_xpub = seedlib.regex_customer_xpub.search(seed_data).groupdict()['xpub']
        
        test_decode = seedlib.mnemonic_decode(encrypted_mnemonic)
        decrypted_seed = seedlib.decode_seed(encrypted_mnemonic, expected_fingerprint, self.stretched_master)
        if not seedlib.fingerprint(decrypted_seed) == expected_fingerprint:
            raise Exception("load_seed: Decrypted seed fingerprint does not match expected fingerprint")
        else:
            print "Loaded seed", expected_fingerprint
            self.seed.from_bin(decrypted_seed)
            self.update_prompt()
            
    def do_save_seed(self, args):
        if not self.seed:
            raise Exception("save_seed: No seed to save")
        interactive.save_seed(self.seed, self.stretched_master.bin_seed())

        
    def complete_load_seed(self, text, line, begidx, endidx):
        files = glob.glob(seedlib.seed_filename_template % "*")
        if not text:
            return files
        else: 
            return [f for f in files if f.startswith(text)]
        
        
    def do_generate_master(self, arg):
        self.master.from_bin(interactive.generate_master())
        self.update_prompt()
        print "Loading seed into shell..."
        
            
    def do_load_master(self, filename):
        if not filename or not os.path.isfile(filename): 
            raise Exception("load_master requires a filename")
        
        if self.master:
            if raw_input("Overwrite existing master? (y/N): ") not in ["y","Y"]:
                raise Exception("aborting load. Keeping existing master seed %s" % self.master_fingerprint)
        
        m = seedlib.regex_master_filename_fingerprint.search(filename)
        expected_fingerprint = m.groupdict()['fingerprint']
        decrypted_master = seedlib.gpg_decrypt_master(expected_fingerprint)
        if not seedlib.fingerprint(decrypted_master) == expected_fingerprint:
            raise Exception("load_master: error, failed to load master seed with correct fingerprint")
        else:
            print "Loaded master seed", expected_fingerprint
            self.master.from_bin(decrypted_master)
            self.update_prompt()
            
         
    def complete_load_master(self, text, line, begidx, endidx):
        files = glob.glob(seedlib.master_filename_template % "*")
        if not text:
            return files
        else: 
            return [f for f in files if f.startswith(text)]
       
        
    def do_save_master(self, args):
        if not self.master:
            raise Exception("save_master: No master seed is loaded. Load or generate a master seed")
        
        encrypted_master = seedlib.gpg_encrypt_master(self.master.as_hex())
        interactive.save_master(self.master.fingerprint(), encrypted_master)
        
    
    def do_stretch_master(self, arg=None):
        if not self.master:
            raise Exception("stretch_master: Load or generate a master seed first")
        if not self.stretched_master:
            self.stretched_master.from_bin(interactive.stretch_master(self.master.as_hex()))
        self.update_prompt()
    
    def do_show_seed_xpub(self, args):
        if not self.seed:
            raise Exception("show seed xpub: Load or generate a seed first")
        
        master_xpriv = self.seed.as_HD_root()
        master_xpub = bitcoin.bip32_privtopub(master_xpriv)
        # Child key m/0'
        xpriv_0H = bitcoin.bip32_ckd(master_xpriv, 2**31)
        xpub_0H = bitcoin.bip32_privtopub(xpriv_0H)
        print "xpub M/0':", xpub_0H
        
    def help_generate_master(self):
        print "Generate master seed"

    
    
def main():
    cmdshell = SeedShell()
    cmdshell.do_reset_seeds()
    cmdshell.update_prompt()
    cmdshell.cmdloop()
 
    
if __name__ == "__main__":
    main()