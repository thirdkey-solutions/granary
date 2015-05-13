import os
import subprocess
import seedlib
import logging
import itertools
from binascii import hexlify, unhexlify


def ssss_installed():
    return any(os.path.isfile(path+'/ssss-split') for path in os.environ['PATH'].split(':')) 
        
def ssss_split(binary_key):
    p = subprocess.Popen(["ssss-split", "-n", str(seedlib.total_shares), "-t", str(seedlib.quorum_shares), "-s", "256", "-x", "-Q"], shell=False, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    p.stdin.write(hexlify(binary_key))
    p.stdin.close()
    p.wait()
    out = p.stdout.read().strip()
    if (p.returncode):
        raise Exception("ssss-combine error: " + out)
    
    # split shares
    indexed_hex_shares = out.strip().split("\n")
    assert(len(indexed_hex_shares) == seedlib.total_shares)
    
    # remove index prefix from shares and convert to 256-bit binary 
    unindexed_binary_shares = [unhexlify(s[2:]) for s in indexed_hex_shares]
    return unindexed_binary_shares
    

def ssss_combine(indexed_hex_shares):
    p = subprocess.Popen(["ssss-combine", "-n", str(seedlib.total_shares), "-t", str(seedlib.quorum_shares), "-s", "256", "-x", "-Q"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    for share in indexed_hex_shares:
        p.stdin.write(share + "\n")
    p.stdin.close()
    p.wait()
    out = p.stdout.read().strip()
    if (p.returncode):
        raise Exception("ssss-combine error: " + out)
     
    hex_key = out  
    assert(len(hex_key) == 64)
    binary_key = unhexlify(hex_key)
    return binary_key
    
    
def ssss_combine_unindexed(unindexed_binary_shares, fingerprint):
    assert(len(unindexed_binary_shares) >= seedlib.quorum_shares)
    unindexed_binary_shares = unindexed_binary_shares[:seedlib.quorum_shares]
    unindexed_hex_shares = list(map(hexlify,unindexed_binary_shares))
    
    indexes = [ str(i) + "-" for i in range(1, 1 + seedlib.total_shares)]
    
    permuted_indexes = list(itertools.permutations(indexes, seedlib.quorum_shares))
    
    for permutation in permuted_indexes:
        indexed_hex_shares = sorted([ i + s for (i,s) in list(itertools.izip(list(permutation), unindexed_hex_shares))])
        try:
            test_key = ssss_combine(indexed_hex_shares)
            if (seedlib.fingerprint(test_key) == fingerprint):
                return test_key
        except Exception as e:
            raise e
    raise Exception("Failed to reconstruct key from shares!")

