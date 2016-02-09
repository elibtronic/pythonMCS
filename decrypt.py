# Command Line utility to Decrypt
from mc_core import *
import sys

def print_usage():
	print "\n\tUsage: python decrypt.py private_key encrypted_file"
	print "\tOutputs decode file\n"

if __name__ == "__main__":
	if len(sys.argv) < 2:
		print_usage()
		exit()
	else:
		tPriv = privateKeyH84()
		tPriv.readKeyFromFile(sys.argv[1])
		print "Decrypting... ",
		tPriv.decryptFile(sys.argv[2])
		print "Done"
