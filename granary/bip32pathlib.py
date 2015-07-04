from binascii import hexlify, unhexlify

class BIP32Path(object):
    def __init__(self):
        self._path = []
    
    def from_string(self, pathstring):
        path_elements = pathstring.split('/')
        self._path = [2**31 + long(child[:-1]) if child[-1:] in "hp'HP" else long(child) for child in path_elements]
    
    def to_string(self):
        return '/'.join([str(child - 2**31) + "'" if child >= 2**31 else str(child) for child in self._path])
        
    def from_hex(self, hex_serialized):
        self._path = [long(unhexlify(hex_serialized[i:i+8])) for i in range(0, len(hex_serialized), 8)]
        
    def to_hex(self):
        return ''.join(["%08x" % child for child in self._path])
        
        

if __name__ == "__main__":
    testpath = BIP32Path()
    path = "0p/3H/1/0/1/2/3/4/0P/4h/0'/0'/0"
    print path
    testpath.from_string(path)
    print testpath.to_string()
    hexpath = testpath.to_hex()
    print hexpath
    testpath.from_hex(hexpath)
    print testpath.to_string()
    
        
        