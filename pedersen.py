# uses pycryptodome, NOT pycrypto
from ecpy.curves import Curve
import random


class Pedersen:
    def __init__(self):
        self.cp = Curve.get_curve("secp256k1")

        self.param = self.setup()

    def setup(self):
        # 2^256
        size = 2**self.cp.size

        # Order of the group to sample Z_p from
        p = self.cp.order

        # Generator of group
        g = self.cp.generator

        # Random scalar from G (Blinding factor)
        r = random.randint(1, size)
        # Random generator value
        h = g * r

        return p, g, h

    def create_commit(self, param, m, r):
        _, g, h = param
        # Create to scalar points on the curve
        mg = self.cp.mul_point(m, g)
        rh = self.cp.mul_point(r, h)

        # Commitment which is the two points on the curve
        c = self.cp.add_point(mg, rh)

        return c, r

    # r is number.getRandomRange(1, p - 1)
    def commit(self, param, m):
        p, _, _ = param

        # Randomness of Z_p
        r = random.randint(1, p-1)

        c, _ = self.create_commit(param, m, r)

        return c, r

    def open(self, param, m, c, r):
        o, _ = self.create_commit(param, m, r)

        # Check if the commitment is valid
        if o == c:
            return True
        else:
            return False

    def add(self, c1, c2):
        # Add two commitments
        return self.cp.add_point(c1, c2)

    def sub(self, c1, c2):
        return self.cp.sub_point(c1, c2)
