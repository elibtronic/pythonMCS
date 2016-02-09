# Demo - Encrypts/Crack Private Key/Decrypt with Cracked key
# 	Combines two previous demos. ie, encrypt file, attempt to crack
# 	the key that encoded it, and then attempt to decrypt that file
# 	with the cracked key
from mc_core import *

tPriv = privateKeyH84()
tPub = publicKeyH84(tPriv.makeGPrime())
print "Encrypting..."
tPub.encryptFile("caesar_letter.txt")
print "Attempting to Crack..."
brute = bruteForcerH84(tPub.GPrime)
brute.attemptKey()
print "Found key in: " + str(brute.attempts) + " attempts.\n"
crackedPriv = privateKeyH84(brute.sConsider,brute.pConsider)
print "Decrypting with Cracked Key..."
crackedPriv.decryptFile("caesar_letter.txt.ctxt")
