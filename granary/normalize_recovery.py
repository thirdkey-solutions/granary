import sys
import os
import json
from bip32pathlib import BIP32Path

def normalize(infile, outfile=None):
    # Load
            in_name = infile
            if os.path.isfile(in_name):
                in_f = open(in_name, 'r')
                recovery_package = json.load(in_f)
            else:
                raise Exception("Can't load recovery file %s" % fname)

    # normalize
            assert 'header' in recovery_package
            header = recovery_package['header']
            assert 'txs' in recovery_package
            txs = recovery_package['txs']
            assert len(txs)
            print('- processing %d transactions' % len(txs))

            header_attribs = ['checksum', 'merkle_root', 'total_out','original_master_xpubs','destination_master_xpubs']
            for header_attrib in header_attribs:
                print("- checking header attribute " + header_attrib)
                if header_attrib not in header:
                    print("- adding the missing header attribute " + header_attrib)
                    header[header_attrib] = None
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

                tx_attribs_opt = ['input_txs','output_paths','scripts']
                missing_opt_attribs = set(tx_attribs_opt) - set(tx.keys())
                for a in missing_opt_attribs:
                    print('- adding missing tx attribute %s in transaction %d' % (a, idx))
                    tx[a] = None
                norm_txs.append(tx)
            recovery_package['txs'] = norm_txs

    # Save
            out_name = in_name[:-4] + '-norm.txs' if not outfile else outfile
            out_f = open(out_name, 'w')
            json.dump(recovery_package, out_f, indent=4)
            #print(json.dumps(recovery_package, indent=4))
            print("Saving to file " + out_name)
            out_f.close()



if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: %s RECOVERY_FILE\n Process a recovery file (JSON encoded) and normalize the contents")
        sys.exit(1)
    else:
        normalize(sys.argv[1])
