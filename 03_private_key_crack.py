# Demo - Brute Force Public Key from Private Key
# 	Attempts to reconstitute a private key from a given Public Key
from mc_core import *

tPriv = privateKeyH84()
tPriv.printCode()
brute = bruteForcerH84(tPriv.makeGPrime())
print("Attempting to Crack...")
brute.attemptKey()
brute.printCode()
