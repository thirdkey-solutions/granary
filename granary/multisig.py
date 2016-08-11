import bitcoin
import re
from binascii import hexlify, unhexlify

def decode_redeem_script(redeemScript):
    if re.match('^[0-9a-fA-F]*$', redeemScript):
        redeemScript = unhexlify(redeemScript)
    if (redeemScript[-1] != unhexlify("AE")): # OP_CHECKMULTISIG
        raise Exception("Not an OP_CHECKMULTISIG redeemScript")
    M = int(hexlify(redeemScript[0])) - 50
    N = int(hexlify(redeemScript[-2])) - 50
    assert (M <= N)
    assert (0 < M <= 15)
    assert (0 < N <= 15)
    raw_pubkeys = hexlify(redeemScript[1:-2])
    pubkeys = [''.join(x[2:]) for x in zip(*[list(raw_pubkeys[z::68]) for z in range(68)])]
    return (M, N, pubkeys)
    
def decode_multisig_script(script):
    scriptSig = bitcoin.deserialize_script(script)
    redeemScript = hexlify(scriptSig[-1])
    (M, N, pubkeys) = decode_redeem_script(redeemScript)
    sigs = []
    for sig in scriptSig[1:-1]:
        sigs.append(hexlify(sig))
    return (sigs, pubkeys, redeemScript, M, N)
    
    
    
    
    
    

    
    

    