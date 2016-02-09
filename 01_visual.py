# Demo - Visual Display
# 	Basic Demo to show how 4 binary digits encode to 8 binary digits
# 	and the decode process
from mc_core import *

m = np.matrix([
[0,1,1,0]
],dtype=int)
print "Message Text:\t",m
tPriv = privateKeyH84()
tPub = publicKeyH84(tPriv.makeGPrime())
ct = tPub.encrypt(m)
print "Cipher Text:\t",ct
mt = tPriv.decrypt(ct)
print "Decoded Text:\t",mt
