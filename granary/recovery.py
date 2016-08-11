import sys
import os
import json
import bitcoin
import multisig
import seedlib
from binascii import hexlify, unhexlify
from bip32pathlib import BIP32Path

def value_print(satoshi):
    return("%12d satoshi (%2.4f BTC)" % (satoshi, satoshi/float(10**8)))
    
def load_recovery(filename):
    if os.path.isfile(filename):
        in_f = open(filename, 'r')
        recovery_package = json.load(in_f)
        return recovery_package
    else:
        raise Exception("Can't load recovery file %s" % filename)
        
def save_recovery(recovery_package, filename):
    if not os.path.isfile(filename):
        out_f = open(filename, 'w')
        json.dump(recovery_package, out_f, indent=2)
        out_f.close()
    else:
        raise Exception("Recovery file %s already exists" % filename)

def normalize(recovery_package):
    # normalize
    assert 'header' in recovery_package
    header = recovery_package['header']
    assert 'txs' in recovery_package
    txs = recovery_package['txs']
    assert len(txs)
    print('- processing %d transactions' % len(txs))

    assert 'merkle_root' in header
    recovery_package['header'] = header

    norm_txs = []
    for idx, tx in enumerate(txs):
        print("- checking transaction %d" % idx)
        tx_attribs_req = ['bytes', 'input_paths']
        missing_req_attribs = set(tx_attribs_req) - set(tx.keys())
        if missing_req_attribs:
            raise Exception('Missing required transaction attributes ' + missing_req_attribs + " in transaction " + idx)

        # normalize BIP32Paths
        norm_paths = []
        for path in tx['input_paths']:
            new_path = BIP32Path.parse(path)
            print("Normalized path: ", new_path.to_slashpath(hardened_suffix="H"))
            norm_paths.append(new_path.to_slashpath(hardened_suffix="H"))
        tx['input_paths'] = norm_paths
        norm_txs.append(tx)
    recovery_package['txs'] = norm_txs
    return recovery_package
    
def validate(recovery_package):
    package_out = 0
    total_out = 0
    total_in = 0
    total_fee = 0
    raw_txs = recovery_package['txs']
    print "Validating %d transactions" % len(raw_txs)
    for tx_index, tx_raw in enumerate(raw_txs):
        print "\nTransaction #", tx_index
        tx = bitcoin.transaction.deserialize(unhexlify(tx_raw['bytes']))
        tx_out = 0
        tx_in = 0
        tx_fee = 0
        for inp in tx['ins']:
            tx_hash = inp['outpoint']['hash']
            vout = inp['outpoint']['index']
            print "\tInput", hexlify(tx_hash) + ":" + str(vout)
            try:
                intx_hex = bitcoin.fetchtx(tx_hash)
                intx = bitcoin.transaction.deserialize(unhexlify(intx_hex))
                prev_out = intx['outs'][vout]
                print "\t  paying " + value_print(prev_out['value']), "to",  bitcoin.script_to_address(prev_out['script'])
                tx_in += prev_out['value']
            except:
                print "Exception in input retrieval - skipping online validation"
                pass    

        if tx_in > 0:
            print "- Total in " + value_print(tx_in)
            total_in += tx_in
        for outp in tx['outs']:
            print "\tOutput paying " + value_print(outp['value']), "to", bitcoin.script_to_address(outp['script'])
            tx_out += outp['value']
        print "- Total out" + value_print(tx_out)
        total_out += tx_out
        tx_size = len(tx_raw['bytes'])/4
        print "- Tx size", tx_size, "bytes"
        if total_in > 0:
            tx_fee = total_in - total_out
            total_fee += tx_fee
            print "- Total fee" + value_print(tx_fee)
            feePerByte = tx_fee / tx_size
            print "- Fee per byte", feePerByte, "satoshi"
            if feePerByte > 100:
                print "WARNING - Excessive fee per byte", feePerByte
            if total_fee > 150000:
                print "WARNING - Unusually large fee", value_print(total_fee)
            if total_fee > (total_out / 100):
                raise Exception("ERROR - Fee exceeds 1% of Tx" + value_print(total_fee))
        
    # check total outputs match expected amount
    print "Total outputs for all transactions", value_print(total_out)
    if total_out == recovery_package['header']['total_out']:
        print "Total outputs for all transactions match the recovery package header"
    else:
        raise Exception("Total outputs for all transactions do not match the recovery package header")
                
def cosign(master_xpriv, recovery_package):
    raw_txs = recovery_package['txs']
    print "Signing %d transactions" % len(raw_txs)
    for tx_index, tx_raw in enumerate(raw_txs):
        print "\nTransaction #", tx_index
        hex_tx = tx_raw['bytes']
        tx = bitcoin.transaction.deserialize(unhexlify(hex_tx))
        keypaths = tx_raw['input_paths']
        keypairs = {}
        for p in keypaths:
            xpriv = seedlib.bip32_child(master_xpriv, p)
            priv = bitcoin.bip32_extract_key(xpriv)
            pub = bitcoin.privtopub(priv)
            keypairs[pub] = priv
        for i, inp in enumerate(tx['ins']):
            (sigs, pubkeys, redeemScript, M, N) = multisig.decode_multisig_script(inp['script'])
            for p in pubkeys:
                if p in keypairs:
                    sig_new = bitcoin.multisign(hex_tx, i, redeemScript, keypairs[p])
                    sigs.append(sig_new)
                    tx_new = bitcoin.apply_multisignatures(unhexlify(hex_tx), i, redeemScript, sigs)
                    print "Signed transaction %d input %d" % (tx_index, i)
        
                    # replace tx with newly signed transaction
                    hex_tx = hexlify(tx_new)
        recovery_package['txs'][tx_index]['bytes'] = hex_tx
    return recovery_package

