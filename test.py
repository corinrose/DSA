from codecs import encode, decode
from dsa import gen_param, gen_keypair, sign, verify, q, p, g

#q, p, g = gen_param()

print(q, p ,g)

message = 256

privkey, pubkey = gen_keypair(q, p, g)

r, s = sign(q, p, g, privkey, message)

print(verify(q, p, g, pubkey, r, s, message))
