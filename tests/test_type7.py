import random
import unittest

from ciscoaudit import type7


class Type7Tests(unittest.TestCase):
    def test_decodes_known_vectors(self):
        # Two different seeds; both strings decode to the word "cisco".
        self.assertEqual(type7.decode("0822455D0A16"), "cisco")
        self.assertEqual(type7.decode("060506324F41"), "cisco")

    def test_round_trip_for_every_seed(self):
        rng = random.Random(7)
        for seed in range(53):
            secret = "".join(rng.choice("abcXYZ019!-_") for _ in range(rng.randint(1, 20)))
            self.assertEqual(type7.decode(type7.encode(secret, seed)), secret)

    def test_rejects_things_that_are_not_type7(self):
        for value in ("cisco", "", "0822455D0A1", "99AABB", "$1$mERr$abc", "08ZZ"):
            self.assertIsNone(type7.decode(value), value)
            self.assertFalse(type7.is_type7(value), value)

    def test_is_type7_accepts_real_shapes(self):
        self.assertTrue(type7.is_type7("0822455D0A16"))
        self.assertTrue(type7.is_type7(type7.encode("admin", 11)))


if __name__ == "__main__":
    unittest.main()
