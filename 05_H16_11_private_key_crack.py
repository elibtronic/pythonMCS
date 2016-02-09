# Demo - Brute Force Public Key from Private Key
# 	Attempts to reconstitute a private key from a given Public Key
#	Based on H16,11 code, will need considerably more time then H8,4
from mc_core import *

tPriv = privateKeyH1611()
tPriv.printCode()
brute = bruteForcerH1611(tPriv.makeGPrime())
print "Attempting to Crack..."
brute.attemptKey()
brute.printCode()
