import unittest

from ciscoaudit.md5crypt import md5_crypt, split_hash


class Md5CryptTests(unittest.TestCase):
    def test_matches_openssl_passwd_1(self):
        # Reference values produced with: openssl passwd -1 -salt <salt> <password>
        vectors = [
            ("cisco", "mERr", "$1$mERr$hx5rVt7rPNoS4wqbXKX7m0"),
            ("password", "3azHgidD", "$1$3azHgidD$SrJPt7B.9rekpmwJwtON31"),
            ("a-much-longer-passphrase-than-sixteen-chars", "abcdefgh", "$1$abcdefgh$Ls8AB/phYKjCiSCXppbr./"),
            ("", "xy", "$1$xy$JSgu5Zv4igzK2ULm5nTM30"),
        ]
        for password, salt, expected in vectors:
            self.assertEqual(md5_crypt(password, salt), expected, password)

    def test_split_hash(self):
        self.assertEqual(split_hash("$1$mERr$hx5rVt7rPNoS4wqbXKX7m0"), ("mERr", "hx5rVt7rPNoS4wqbXKX7m0"))
        for bad in ("cisco", "$5$abc$def", "$1$$x", "$1$salt$"):
            self.assertIsNone(split_hash(bad), bad)


if __name__ == "__main__":
    unittest.main()
