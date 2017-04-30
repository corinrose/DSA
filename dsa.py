#    Corin Rose
#    <crose@vassar.edu>

#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.

#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.

#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

#!/usr/bin/python3

from hashlib import sha256
from codecs import encode
from random import getrandbits, randint
from gmpy2 import is_prime

q = 251
p = 503
g = 4

def gen_param(N = 160, L = 1024):

    q = getrandbits(N)
    while not(is_prime(q)):
        q = getrandbits(N)

    i = 2**1024
    p = getrandbits(L)
    while not(is_prime(p)):
        i += 1
        p = q*i + 1

    g = pow(2, i, p)

    return q, p, g

def hashint(m):
    m = m.to_bytes(m.bit_length(), byteorder='big')
    m = sha256(m).digest()
    m = int.from_bytes(m, byteorder='big')
    return m
 
# only works for prime modulus, which is all that's needed for DSA
def invert(n, p):
    totient = p-1
    # thanks to fermat
    inverse = pow(n, totient - 1, p)
    return inverse
 
def gen_keypair(q, p, g):
    privkey = randint(0, q)
    pubkey = pow(g, privkey, p)
    return (privkey, pubkey)
 
def sign(q, p, g, privkey, message):
    k = randint(0, q)
    r = pow(g, k, p) % q
    s = (invert(k, q) * (hashint(message) + privkey*r)) % q
    return (r, s)
 
def verify(q, p, g, pubkey, r, s, message):
    w = invert(s, q)
    u1 = hashint(message)*w % q
    u2 = r*w % q
    v = (pow(g, u1)*pow(pubkey, u2) % p) % q
    return v == r

