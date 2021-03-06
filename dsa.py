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

#!/usr/bin/python2

from hashlib import sha256
from codecs import encode
from random import getrandbits, randint
from miller_rabin import isPrime

q = 251
p = 503
g = 4

def gen_param(N = 160, L = 1024):

    q = getrandbits(N)
    while not(isPrime(q)):
        q = getrandbits(N)

    i = 2**L
    p = 0
    while not(isPrime(p)):
        i += 1
        p = q*i + 1

    g = pow(2, i, p)

    return q, p, g

def hash(m):
    # sha256 takes in binary, so we have to convert our int
    # the commented out way is python3 compatible, the way we're using
    # is python2 - this is the ONE LINE of the code that isn't cross-compatible :(
    # m = m.to_bytes()
    m = bin(m)
    m = sha256(m).hexdigest()
    # now our m is a string that represents a hexadecimal number,
    # luckily python has a nice way to convert that to a decimal int
    m = int(m, 16)
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
    s = (invert(k, q) * (hash(message) + privkey*r)) % q
    return (r, s)
 
def verify(q, p, g, pubkey, r, s, message):
    w = invert(s, q)
    u1 = hash(message)*w % q
    u2 = r*w % q
    v = (pow(g, u1, p)*pow(pubkey, u2, p) % p) % q
    return v == r

