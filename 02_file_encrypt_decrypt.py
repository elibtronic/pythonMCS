# Demo - File Based
# 	Demostrates file encryption/decryption
from mc_core import *

tPriv = privateKeyH84()
tPub = publicKeyH84(tPriv.makeGPrime())
print("Encrypting...")
tPub.encryptFile("caesar_letter.txt")
print("Decrypting...")
tPriv.decryptFile("caesar_letter.txt.ctxt")
