import base64
import unittest

import ctf_encoding as ce


class TestDecoders(unittest.TestCase):
    def test_base64(self):
        self.assertEqual(ce.dec_base64("SGVsbG8gIQ=="), "Hello !")

    def test_base32(self):
        self.assertEqual(ce.dec_base32("JBSWY3DP"), "Hello")

    def test_hex_with_separators(self):
        self.assertEqual(ce.dec_hex("48 65 6c 6c 6f"), "Hello")
        self.assertEqual(ce.dec_hex("0x48:0x69"), "Hi")

    def test_binary(self):
        self.assertEqual(ce.dec_binary("01001000 01101001"), "Hi")

    def test_url(self):
        self.assertEqual(ce.dec_url("a%20b%3Dc"), "a b=c")

    def test_rot13_is_its_own_inverse(self):
        self.assertEqual(ce.dec_rot13("Uryyb, Jbeyq!"), "Hello, World!")
        self.assertEqual(ce.dec_rot13(ce.dec_rot13("Test")), "Test")

    def test_invalid_input_raises(self):
        for fn, bad in ((ce.dec_base64, "pas du base64 !"), (ce.dec_binary, "0102"), (ce.dec_hex, "zz")):
            with self.assertRaises(ValueError):
                fn(bad)


class TestAuto(unittest.TestCase):
    def test_chained_decoding(self):
        secret = "flag{couches_multiples}"
        layered = base64.b64encode(secret.encode().hex().encode()).decode()  # base64( hex( texte ) )
        results = ce.auto_decode(layered)
        self.assertEqual(results[0][1], secret)
        self.assertEqual(results[0][0], ("base64", "hex"))

    def test_find_flags(self):
        self.assertEqual(ce.find_flags("blabla CTF{abc_123} et flag{xyz}"), ["CTF{abc_123}", "flag{xyz}"])

    def test_rot13_is_kept_only_when_it_reveals_a_flag(self):
        self.assertEqual(ce.auto_decode("synt{pbhpbh}")[0], (("rot13",), "flag{coucou}"))
        self.assertNotIn("rot13", [c for chain, _ in ce.auto_decode("flag{deja_en_clair}") for c in chain])

    def test_nothing_readable(self):
        self.assertEqual(ce.auto_decode("zzzz zzzz"), [])


class TestXor(unittest.TestCase):
    def test_roundtrip(self):
        data = b"message secret"
        self.assertEqual(ce.xor_bytes(ce.xor_bytes(data, b"cle"), b"cle"), data)

    def test_empty_key_refused(self):
        with self.assertRaises(ValueError):
            ce.xor_bytes(b"abc", b"")

    def test_single_byte_crack(self):
        plain = b"The quick brown fox jumps over the lazy dog, and then it goes back home."
        encrypted = ce.xor_bytes(plain, bytes([0x2A]))
        key, text, _ = ce.xor_single_byte_crack(encrypted)[0]
        self.assertEqual(key, 0x2A)
        self.assertEqual(text.encode("latin-1"), plain)


if __name__ == "__main__":
    unittest.main()
