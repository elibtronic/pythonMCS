# Command Line utility to Encrypt
from mc_core import *
import sys

def print_usage():
	print "\n\tUsage: python encrypt.py input_file\n"
	print "\tSpits out three files:"
	print "\t\tinput_file.priv - private key"
	print "\t\tinput_file.pub - public key"
	print "\t\tinput_file.ctxt - encrypted file\n"

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print_usage()
		exit()
	else:
		tPriv = privateKeyH84()
		tPub = publicKeyH84(tPriv.makeGPrime())
		print "Encrypting... ",
		tPub.encryptFile(sys.argv[1])
		tPriv.writeKeyToFile(str(sys.argv[1])+".priv")
		tPub.writeKeyToFile(str(sys.argv[1])+".pub")
		print "Done"
