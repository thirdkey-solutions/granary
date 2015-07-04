#! env python

import glob, os
import json
from binascii import hexlify, unhexlify
from cmd2 import Cmd
import getpass
import bitcoin

import seedlib
from seed import Seed
import ssss_wrapper


class SeedShell(Cmd):
    
    intro = """
    Granary is an interactive shell for managing seeds for use in crypto-currencies.
    
    Glossary: 
        - Master seed: A seed used to encrypt other seeds
        - Stretched Master: The master seed, stretched by a passphrase
        - Seed: A seed encrypted with the stretched master and used to derive BIP32 keys (xpriv/xpub)
        
    Process:
        Try the following commands to build a seed
        
        Step 1. Generate or load a master encryption seed
            Commands: generate_master, master_from_shares, load_master, save_master
            
        Step 2. stretched the master seed
            Command: stretch_master
             
        Step 3. Generate or load a seed for customer keys: 
            Commands: generate_seed, load_seed, save_seed, show_seed_xpub
            
        Use command "seeds" to see the fingerprints of all loaded seeds
            
        Or enter "help" for a list of commands, "help <command>" for a description of each command
        eg. help seeds
    
    """
    
    
    def do_reset_seeds(self):
        self.master = Seed()
        self.stretched_master = Seed()
        self.seed = Seed()
        self.update_prompt()
        
        
    def help_reset_seeds(self):
        print "Reset all stored seeds"
        
               
    def update_prompt(self):
        prompt = "granary "
        if self.stretched_master:
            prompt += "SM-%s" % self.stretched_master.fingerprint()
            prompt += "# "
        elif self.master:
            prompt += "M-%s" % self.master.fingerprint()
            prompt += "$ "
        else:
            prompt +="$ "
        self.prompt = prompt
        
        
    def do_seeds(self, arg=None):
        print "Seeds loaded"
        print "-" * 20
        print "Master           : ", self.master.fingerprint() or "None"
        print "Stretched Master : ", self.stretched_master.fingerprint() or "None"
        print "Seed             : ", self.seed.fingerprint() or "None"
        print "-" * 20
        
        
    def help_seeds(self):
        print "Show all stored seed fingerprints"
        
        
    def do_generate_master(self, arg):
        print "===== Generating Master"
        self.master.from_random()

        print "===== Splitting Master into mnemonic shares"
        mnemonic_share_list = seedlib.split(self.master.bin_seed())
    
        print "===== Printing shares for key fingerprint", self.master.fingerprint()
        for i in range(5):
            print "\n"
            print i+1,".", mnemonic_share_list[i]
        print "\n"    
        self.update_prompt()
        
        
    def help_generate_master(self):
        print "Generate a new master seed from entropy"
        
            
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
            
            
    def help_load_master(self):
        print "Load a PGP encrypted master seed from a file" 
         
            
    def do_master_from_shares(self, args):
        if self.master:
            if raw_input("Overwrite existing master? (y/N): ") not in ["y","Y"]:
                raise Exception("aborting load. Keeping existing master seed %s" % self.master_fingerprint)
        
        expected_fingerprint = str(raw_input("Enter master fingerprint: ")).upper()
        shares = []
        while (len(shares) < seedlib.quorum_shares):
            need = seedlib.quorum_shares - len(shares)
            try:     
                share = str(raw_input("Enter a key share  ("+str(need)+" more needed): "))
                decoded_share = seedlib.mnemonic_decode(share)
                shares.append(decoded_share)
            except KeyboardInterrupt:
                raise
            except Exception as e:
                print e, "... try again"
    
        print "Reconstructing key"
        master_bin_seed = ssss_wrapper.ssss_combine_unindexed(shares, expected_fingerprint)
        self.master.from_bin(master_bin_seed)
        self.update_prompt()


    def help_master_from_shares(self):
        print "Reconstruct a master seed from M-of-N mnemonic shares" 
     
        
    def do_save_master(self, args):
        if not self.master:
            raise Exception("save_master: No master seed is loaded. Load or generate a master seed")
        
        encrypted_master = seedlib.gpg_encrypt_master(self.master.as_hex())
        print "Storing encrypted master"
        keyfilename = seedlib.master_filename_template % self.master.fingerprint()
        keyfile = open(keyfilename,'w')

        key_json = {
            "fingerprint" : self.master.fingerprint(),
            "pgp" : str(encrypted_master),
        }
        key_text = json.dumps(key_json, sort_keys=True, indent=2)
        keyfile.write(key_text)
        keyfile.close
        print key_text
        print "Data saved to ", keyfilename
        

    def help_save_master(self):
        print "Save a PGP encrypted master seed to a file" 
        
    
    def do_stretch_master(self, arg=None):
        if not self.master:
            raise Exception("stretch_master: Load or generate a master seed first")
        passphrase = getpass.getpass("Type passphrase for master key stretching: ")
        passphrase = seedlib.mnemonic.normalize_string(passphrase)
        print "Password stretching, please wait, may take a while"
        self.stretched_master.from_bin(seedlib.stretched_key(self.master.bin_seed(), passphrase))
        print "Stretched key fingerprint: ", self.stretched_master.fingerprint()
        self.update_prompt()
        
        
    def help_stretch_master(self):
        print "Generate a stretched key by stretching the master with a passphrase"
        
        
    def do_generate_seed(self, args):
        if not self.stretched_master:
            raise Exception("generate_seed: stretch a master seed first")
                    
        # generate seed
        print "Generating customer seed"
        self.seed.from_random()

        print "Customer key fingerprint:", self.seed.fingerprint()

        print "Encrypting customer seed"
        encrypted_customer_seed = seedlib.encrypt(self.seed.bin_seed(), self.stretched_master.bin_seed())

        print "Creating encrypted mnemonic"
        encrypted_mnemonic = seedlib.mnemonic.to_mnemonic(encrypted_customer_seed)
        print encrypted_mnemonic

        print "Decrypting seed"
        decrypted_seed = seedlib.decode_seed(encrypted_mnemonic, self.seed.fingerprint(), self.stretched_master.bin_seed())

        print "Running validation tests"
        assert(decrypted_seed == self.seed.bin_seed())
    
        print "Validation tests completed successfully"
        
        
    def help_generate_seed(self):
        print "Generate a seed from entropy and encrypt it with a stretched master key"
        
        
    def do_load_seed(self, filename):
        if not self.master:
            raise Exception("password: Load the master seed first")
            
        if not filename or not os.path.isfile(filename): 
            raise Exception("load_seed requires a filename")
        
        m = seedlib.regex_seed_filename_fingerprint.search(filename)
        expected_fingerprint = m.groupdict()['fingerprint']
        
        seed_file = open(filename, 'r')
        seed_data = json.loads(seed_file.read())
        seed_file.close()
                
        expected_fingerprint = seed_data['fingerprint']
        encrypted_mnemonic = seed_data['encrypted_mnemonic']
        expected_master = seed_data['master']
        expected_stretched_master = seed_data['stretched_master']
        
        if expected_stretched_master != self.stretched_master.fingerprint():
            raise Exception("load_seed: Seed is encrypted with a different stretched master than the one currently loaded")
        
        decrypted_seed = seedlib.decode_seed(encrypted_mnemonic, expected_fingerprint, self.stretched_master.bin_seed())
        if not seedlib.fingerprint(decrypted_seed) == expected_fingerprint:
            raise Exception("load_seed: Decrypted seed fingerprint does not match expected fingerprint")
        else:
            print "Loaded seed", expected_fingerprint
            self.seed.from_bin(decrypted_seed)
            self.update_prompt()
            
            
    def help_load_seed(self):
        print "Load an encrypted seed from a file and decrypt it with the stretched master key"
            
        
    def do_save_seed(self, args):
        if not self.seed:
            raise Exception("save_seed: No seed to save")
            
        print "Storing seed"
        keyfilename = seedlib.seed_filename_template % self.seed.fingerprint()
        keyfile = open(keyfilename,'w')
    
        encrypted_customer_seed = seedlib.encrypt(self.seed.bin_seed(), self.stretched_master.bin_seed())
        encrypted_mnemonic = seedlib.mnemonic.to_mnemonic(encrypted_customer_seed)
    
        key_json = {
            "fingerprint"           : self.seed.fingerprint(),
            "master"                : self.master.fingerprint(),
            "stretched_master"      : self.stretched_master.fingerprint(),
            "encrypted_mnemonic"    : encrypted_mnemonic,
        }
        key_text = json.dumps(key_json, indent=2)
        keyfile.write(key_text)
        keyfile.close
        print "Data saved to ", keyfilename
        print key_text
        
        
    def help_save_seed(self):
        print "Save an encrypted seed to a file"

        
    def complete_load_seed(self, text, line, begidx, endidx):
        files = glob.glob(seedlib.seed_filename_template % "*")
        if not text:
            return files
        else: 
            return [f for f in files if f.startswith(text)]
        
    
    def do_show_seed_xpub(self, args):
        if not self.seed:
            raise Exception("show seed xpub: Load or generate a seed first")
            
        master_xpriv = self.seed.as_HD_root()
        
        if args:
            path = [2**31 + int(child[:-1]) if child[-1:] in "hp'HP" else int(child) for child in args.split('/')]
            for p in path:
                master_xpriv = bitcoin.bip32_ckd(master_xpriv, p)
            
        master_xpub = bitcoin.bip32_privtopub(master_xpriv)
        
        print "Path %s :" % args if args else "Root key"
        print "public %s" % master_xpub
        print "private %s" % master_xpriv
        
        
    def help_show_seed_xpub(self):
        print "show_seed_xpub [PATH]"
        print "Derive a BIP32 extended key for PATH and display the xpub/xpriv"
        
    def do_cosign_bitoasis(self, args):
        if not self.seed:
            raise Exception("cosign: Load or generate a seed first")
        
        if args and len(args.split()) > 1:
            filename = args.split()[0]
            path = args.split()[1]
        else:
            filename = args
        
        if not filename or not os.path.isfile(filename): 
            raise Exception("cosign: requires a filename")    
        
        master_xpriv = self.seed.as_HD_root()
        
        
        if path:
            path = [2**31 + int(child[:-1]) if child[-1:] in "hp'HP" else int(child) for child in path.split('/')]
            for p in path:
                master_xpriv = bitcoin.bip32_ckd(master_xpriv, p)
        
        import multisigrecovery.commands
        from multisigrecovery.commands import ScriptInputError
        
        class Arguments(object): pass
        args = Arguments()
        args.private = master_xpriv
        args.load = filename
        args.save = filename + '.signed'
        
        multisigrecovery.commands.cosign(args)
        
    def help_cosign_bitoasis(self):
        print "cosign_bitoasis FILENAME [KEYPATH]"
        print "Sign a transaction recovery package contained in FILENAME, using the BIP32 KEYPATH private key derived from seed"
        
        
    def complete_cosign_bitoasis(self, text, line, begidx, endidx):
        files = glob.glob("*")
        if not text:
            return files
        else: 
            return [f for f in files if f.startswith(text)]
        

    
    
def main():
    cmdshell = SeedShell()
    cmdshell.debug = True
    cmdshell.do_reset_seeds()
    cmdshell.update_prompt()
    cmdshell.cmdloop()
 
    
if __name__ == "__main__":
    main()