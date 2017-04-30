from dsa import gen_param, gen_keypair, sign, verify
import sys

print("algorithm parameter generation: ")

if (len(sys.argv) > 1):
    q, p, g = gen_param(int(sys.argv[1]), int(sys.argv[2]))
else:
    # default inputs are (160, 1024)
    q, p, g = gen_param()


print("q: {}\np: {}\ng: {}\n".format(q, p, g))

print("keypair generation:")

privkey, pubkey = gen_keypair(q, p, g)

print("privkey: {}\npubkey: {}\n".format(privkey, pubkey))

message = int(input("enter your message (as an integer): "))

print("\nsigning message with private key {}".format(privkey))

r, s = sign(q, p, g, privkey, message)

print("signature (r, s): {}".format((r, s)))

print("\nverifying message '{}' with signaure {}".format(message, (r, s)))

print(verify(q, p, g, pubkey, r, s, message))
