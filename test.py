from dsa import gen_param, gen_keypair, sign, verify

q = 251
p = 503
g = 4

message = 256

privkey, pubkey = gen_keypair(q, p, g)

r, s = sign(q, p, g, privkey, message)

print(verify(q, p, g, pubkey, r, s, message))
