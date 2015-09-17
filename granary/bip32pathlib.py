from __future__ import print_function
from binascii import hexlify, unhexlify
import string

class ParseError(BaseException):
    pass

class BIP32Path(object):
    def __init__(self):
        self._path = []

    def __len__(self):
        return len(self._path)

    def __iter__(self):
        for p in self._path:
            yield int(p)

    def __repr__(self):
        return "<BIP32Path \"" + self.to_slashpath(hardened_suffix="'") + "\">"

    @classmethod
    def parse(cls, pathstring):
        # determine if hex or slash-separated path
        # pathstring contains no slash, is a multiple of 8 and all hex-digits - this is a hex-encoded path
        if '/' not in pathstring and len(pathstring) % 8 == 0 and all(c in string.hexdigits for c in pathstring):
            if all(c in string.digits for c in pathstring) and 0<=int(pathstring)<=2**32:
                import warnings
                warnings.warn("Ambiguous path \"%s\", may be hex or may be single child integer path" % pathstring, Warning)
            bip32path = cls.from_hexpath(pathstring)
            return bip32path
        # pathstring contains a slash, or a 'hardened' suffix or is an integer - this is a human readable slash-delimited path
        elif '/' in pathstring or any(c in "hHpP'" for c in pathstring) or all(c in string.digits for c in pathstring):
            bip32path = cls.from_slashpath(pathstring)
            return bip32path
        else:
            raise ParseError('Unable to parse - Unknown BIP32 path format')

    @classmethod
    def from_slashpath(cls, slashpath):
        path_elements = slashpath.split('/')
        bip32path = cls()
        bip32path._path = [2**31 + int(child[:-1]) if child[-1:] in "hp'HP" else int(child) for child in path_elements]
        return bip32path

    @classmethod
    def from_hexpath(cls, hex_serialized):
        bip32path = cls()
        bip32path._path = [int(hex_serialized[i:i+8], 16) for i in range(0, len(hex_serialized), 8)]
        return bip32path

    def to_slashpath(self, hardened_suffix = "'"):
        return '/'.join([str(child - 2**31) + hardened_suffix if child >= 2**31 else str(child) for child in self._path])

    def to_hexpath(self):
        return ''.join(["%08x" % child for child in self._path])



if __name__ == "__main__":

    import unittest

    class BIP32PathTest(unittest.TestCase):
        def setUp(self):
            pass

        def test_from_slashpath(self):
            test_path = BIP32Path.from_slashpath("0p/3H/1/0/1/2/3/4/0P/4h/0'/0'/0")
            self.assertEqual(test_path.to_slashpath(), "0'/3'/1/0/1/2/3/4/0'/4'/0'/0'/0")
            self.assertEqual(test_path.to_slashpath(hardened_suffix='p'), "0p/3p/1/0/1/2/3/4/0p/4p/0p/0p/0")

        def test_len(self):
            test_path = BIP32Path.from_slashpath("0p/3H/1/0/1/2/3/4/0P/4h/0'/0'/0")
            self.assertEqual(len(test_path), 13)

        def test_iter(self):
            test_path = BIP32Path.from_slashpath("0p/3H/1/0/1/2/3/4/0P/4h/0'/0'/0")
            for p in test_path:
                self.assertLessEqual(p, 2**32)
                self.assertGreaterEqual(p, 0)
                self.assertIsInstance(p, int)

        def test_repr(self):
            test_path = BIP32Path.from_slashpath("0p/3H/1/0/1/2/3/4/0P/4h/0'/0'/0")
            self.assertEqual(str(test_path), "<BIP32Path \"0'/3'/1/0/1/2/3/4/0'/4'/0'/0'/0\">")


        def test_from_hexpath(self):
            test_path = BIP32Path.from_hexpath("0000000000000001000000028000000080000001")
            self.assertEqual(str(test_path), "<BIP32Path \"0/1/2/0'/1'\">")

        def test_parse(self):
            test_path = BIP32Path.parse("0000000000000001000000028000000080000001")
            self.assertEqual(test_path.to_slashpath(hardened_suffix="'"), "0/1/2/0'/1'")
            test_path = BIP32Path.parse("0p/3H/1/0/1/2/3/4/0P/4h/0'/0'/0")
            self.assertEqual(test_path.to_slashpath(hardened_suffix="'"), "0'/3'/1/0/1/2/3/4/0'/4'/0'/0'/0")
            test_path = BIP32Path.parse("0")
            self.assertEqual(test_path.to_slashpath(hardened_suffix="'"), "0")
            test_path = BIP32Path.parse("0'")
            self.assertEqual(test_path.to_slashpath(hardened_suffix="'"), "0'")
            test_path = BIP32Path.parse("00000000")
            self.assertEqual(test_path.to_slashpath(hardened_suffix="'"), "0")

            # ambiguous 8 character number is interpreted as hex, not integer
            test_path = BIP32Path.parse("80000000")
            self.assertEqual(test_path.to_slashpath(hardened_suffix="'"), "0'")


            self.assertRaises(ParseError, BIP32Path.parse, "#")









    unittest.main()
