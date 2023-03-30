
# Core Library Utilities
import numpy as np
import pickle
import os.path
import random
import csv

###### Helper Functions #######


def genSMatrix(k):
    """Generates an invertable matrix k * k"""
    sMaybe = np.matrix(np.random.randint(0, 2, k*k).reshape(k, k).astype(int))
    while True:
        try:
            sMaybe.getI()
            return sMaybe
        except:
            sMaybe = np.matrix(np.random.randint(
                0, 2, k*k).reshape(k, k).astype(int))


def genPMatrix(n, keep=False):
    """Generates a permutation matrix n x n using the given sequence"""
    p = np.identity(n, dtype=int)
    if keep:
        return np.matrix(p).reshape(n, n)
    else:
        return np.matrix(np.random.permutation(p))


def modTwo(C):
    """Q & D way to Mod 2 all results"""
    D = C.copy()
    D.fill(2)
    return np.remainder(C, D)


def bitFlip(C, n):
    """Flips the bit you tell it, -1 for random bit flip, 0 for no flip"""
    if n == 0:
        return C
    if n == -1:
        index = random.randint(1, C.size - 1)
    else:
        index = n

    if C[0, index-1] == 1:
        C[0, index-1] = 0
    else:
        C[0, index-1] = 1
    return C


def all_zeros(d):
    """Used when looking up a Syndrome, all zeros mean no error"""
    zc = 0
    for x in d:
        if x == 0:
            zc += 1
    if zc == len(d):
        return True
    else:
        return False


def syndromeLookup(H, d):
    """Looks up where in the syndrome table, if not found must be codeword, in that case returns 0"""
    t = H.T.tolist()
    s = d.T.tolist()[0]

    # print "s s\t",s

    if all_zeros(s):
        # print "s i\t 0"
        return 0
    try:
        # print "s i\t ",t.index(s) + 1
        return t.index(s) + 1
    except:
        # print "s i\t 0"
        return 0


def checkOldGuesses(oG, newGuess):
    """Helper function to see if a guessed matrix has been used before"""

    for s in oG:
        if np.array_equal(newGuess.A1, s.A1):
            return False
        else:
            return True


def makeString(matrix):
    """Used in DNA file encoding, will make Numpy Matrix into text strings for easier manipulation"""
    message = ""
    for m in matrix.A1:
        if m == "[":
            pass
        elif m == "]":
            pass
        elif m == " ":
            pass
        else:
            message += str(m)
    return message


#### Hamming 8,4 Encryption Data Structures ######

#### Private Key H84 ####
class privateKeyH84:
    """Datastructure to represent our Private Key"""

    def __init__(self, S=None, P=None):
        """Initalizer that will set S & P matricies to random if not given values"""
        # Hamming 8,4 in standard
        self.G = np.matrix([
            [1, 0, 0, 0, 0, 1, 1, 1],
            [0, 1, 0, 0, 1, 0, 1, 1],
            [0, 0, 1, 0, 1, 1, 0, 1],
            [0, 0, 0, 1, 1, 1, 1, 0]
        ], dtype=int)
        self.H = np.matrix([
            [0, 1, 1, 1, 1, 0, 0, 0],
            [1, 0, 1, 1, 0, 1, 0, 0],
            [1, 1, 0, 1, 0, 0, 1, 0],
            [1, 1, 1, 0, 0, 0, 0, 1]
        ], dtype=int)

        # Can create these from known values, otherwise random
        if S == None:
            self.S = modTwo(genSMatrix(4))
        else:
            self.S = S

        if P == None:
            self.P = modTwo(genPMatrix(8))
        else:
            self.P = P

    def printCode(self):
        """Canonical print to screen function"""
        print("S: \n" + str(self.S) + "\n")
        print("P: \n" + str(self.P) + "\n")
        print("GPrime: \n" + str(self.makeGPrime()) + "\n")

    def writeKeyToFile(self, keyFile):
        """Saves key to a pickle file"""
        try:
            pickle.dump(self, open(keyFile, "wb"))
        except:
            print("Could not save key file to: ", keyFile)
            exit(1)

    def readKeyFromFile(self, keyFile):
        """Reads key from a pickle file"""
        try:
            newPriv = pickle.load(open(keyFile, "rb"))
            self.S = newPriv.S
            self.P = newPriv.P
        except:
            print("Could not load key file from: ", keyFile)
            exit(1)

    def makeGPrime(self):
        """Creates the GPrime encrytion Matrix"""
        return modTwo(self.S*self.G*self.P)

    def decrypt(self, c):
        """When given cipher text will decode to message"""
        cHat = c * modTwo(self.P.I.astype(int))
        m = bitFlip(cHat, syndromeLookup(self.H, modTwo(self.H*cHat.T)))
        return modTwo(m[0, 0:4] * modTwo(self.S.I.astype(int)))

    def decryptFile(self, f):
        """Will decrypt whole file"""
        cf = open(f, "rb")
        cb1 = cf.read(1)
        cb2 = cf.read(1)
        print(cb1)
        print(cb2)
        mf = open(f+".decoded", "wb")

        while cb1 and cb2:
            # First Byte of Cipher Text
            c_1 = '{0:08b}'.format(ord(cb1))[0:8]
            c1_l = []
            m1 = ""
            for s in c_1:
                c1_l.append(s)
            c_1_m = np.matrix(c1_l, dtype=int)

            d1 = self.decrypt(c_1_m)
            #print(d1)
            for d in range(0, d1.size):
                m1 += str(d1.item(d))
            # Second Byte of Cipher Text
            c_2 = '{0:08b}'.format(ord(cb2))[0:8]
            c2_l = []
            m2 = ""
            for s in c_2:
                c2_l.append(s)
            c_2_m = np.matrix(c2_l, dtype=int)

            d2 = self.decrypt(c_2_m)

            for d in range(0, d2.size):
                m2 += str(d2.item(d))
            #print(m1+m2)
            #print(chr(int(m1+m2,2)))
            mf.write(bytes([ord(chr(int(m1+m2, 2)))]))
            cb1 = cf.read(1)
            cb2 = cf.read(1)

        mf.close()
        cf.close()

    def dnaFileDecrypt(self, f, dlu):
        """Decrypts a file that has been turned into a DNA representation"""
        cf = open(f, "r")
        c1 = cf.readline().strip("\n")
        c2 = cf.readline().strip("\n")

        mf = open(f+".decoded", "w")

        while c1 and c2:
            m1 = ""
            m2 = ""
            mat1 = np.matrix(" ".join(dlu.lookDNADecrypt(c1)), dtype=int)
            mat2 = np.matrix(" ".join(dlu.lookDNADecrypt(c2)), dtype=int)
            d1 = self.decrypt(mat1)
            d2 = self.decrypt(mat2)
            for d in range(0, d1.size):
                m1 += str(d1.item(d))

            for d in range(0, d2.size):
                m2 += str(d2.item(d))

            mf.write(bytes(chr(int(m1+m2, 2)), 'utf-8'))
            c1 = cf.readline().strip("\n")
            c2 = cf.readline().strip("\n")

        mf.close()
        cf.close()

#### Public Key H84 ####


class publicKeyH84:
    """Public Key Data Structure"""

    def __init__(self, GPrime):
        self.GPrime = GPrime

    def printCode(self):
        """Canonical print to screen"""
        print("GPrime: \n" + str(self.GPrime) + "\n")

    def writeKeyToFile(self, keyFile):
        """Saves key to a pickle file"""
        try:
            pickle.dump(self, open(keyFile, "wb"))
        except:
            print("Could not save key file to: ", keyFile)
            exit(1)

    def readKeyFromFile(self, keyFile):
        """Reads key from a pickle file"""
        try:
            newPub = pickle.load(open(keyFile, "rb"))
            self.GPrime = newPub.GPrime
        except:
            print("Could not load key file from: ", keyFile)
            exit(1)

    def encrypt(self, m):
        """When given a message will encode"""
        # Error vector will be random
        z = random.randint(1, 7)
        c = bitFlip(modTwo(m*self.GPrime), z)
        return c

    def encryptFile(self, f):
        """Encrypts a whole file"""

        mf = open(f, "rb")
        m = mf.read(1)

        cf = open(f+".ctxt", "wb")

        while m:
            # First half byte of message text
            m_1 = '{0:08b}'.format(ord(m))[0:4]
            m1_l = []
            c1 = ""
            for s in m_1:
                m1_l.append(s)
            m_1_m = np.matrix(m1_l, dtype=int)

            d1 = self.encrypt(m_1_m)
            for d in range(0, d1.size):
                c1 += str(d1.item(d))
            cf.write(bytes([ord(chr(int(c1, 2)))]))
            
            # Second half byte of message text
            m_2 = '{0:08b}'.format(ord(m))[4:]
            m2_l = []
            c2 = ""
            for s in m_2:
                m2_l.append(s)
            m_2_m = np.matrix(m2_l, dtype=int)

            d2 = self.encrypt(m_2_m)
            for d in range(0, d2.size):
                c2 += str(d2.item(d))
            cf.write(bytes([ord(chr(int(c2, 2)))]))
            

            m = mf.read(1)

        cf.close()
        mf.close()

    def dnaFileEncrypt(self, f, dlu):
        """Takes a files, encypts it and represents it as a DNA codeword"""
        cipherString = ""

        mf = open(f, "rb")
        m = mf.read(1)

        cf = open(f+".dna.ctxt", "wb")

        while m:

            # First half byte of message text
            m_1 = '{0:08b}'.format(ord(m))[0:4]
            m1_l = []
            c1 = ""
            for s in m_1:
                m1_l.append(s)
            m_1_m = np.matrix(m1_l, dtype=int)

            d1 = self.encrypt(m_1_m)

            # Second half byte of message text
            m_2 = '{0:08b}'.format(ord(m))[4:]
            m2_l = []
            c2 = ""
            for s in m_2:
                m2_l.append(s)
            m_2_m = np.matrix(m2_l, dtype=int)
            d2 = self.encrypt(m_2_m)

            message = makeString(m_1_m) + makeString(m_2_m)
            cipherMessage = makeString(d1) + makeString(d2)
            cf.write(dlu.lookDNAEncrypt(cipherMessage[0:8])+"\n")
            cf.write(dlu.lookDNAEncrypt(cipherMessage[8:])+"\n")
            m = mf.read(1)

        cf.close()
        mf.close()

#### Brute Forcer ####
        
class bruteForcerH84():
	"""Data structure that attempts to create Private Key from Given Public Key"""
	def __init__(self,GPrime):
		
		self.attempts = 0
		
		self.GPrime = GPrime
		
		self.GPrimeConsider = 0
		self.sConsider = 0
		self.pConsider = 0
		
		self.STries = list()
		self.PTries = list()
		
		self.G = np.matrix([
		[1,0,0,0,0,1,1,1],
		[0,1,0,0,1,0,1,1],
		[0,0,1,0,1,1,0,1],
		[0,0,0,1,1,1,1,0]
		], dtype=int)
		
	def printCode(self):
		"""Canonical Print self function"""
		print("Calculated GPrime:\n" + str(self.GPrimeConsider) + "\n")
		print("sM:\n" + str(self.sConsider) + "\n")
		print("pM:\n" + str(self.pConsider) + "\n")
		print("Attempts: " + str(self.attempts) + "\n")
		
	def attemptKey(self):
		"""Attempts to reconstitute S,P given GPrime (G is already known)"""
		self.attempts = 1
		
		self.sConsider = genSMatrix(4)
		self.STries.append(self.sConsider)
		
		self.pConsider = genPMatrix(8)
		self.PTries.append(self.pConsider)
		
		self.GPrimeConsider = modTwo(self.sConsider*self.G*self.pConsider)
		
		while not np.array_equal(self.GPrimeConsider.A1,self.GPrime.A1):
			
			self.attempts += 1
		
			#Keep generating new S matrices to test
			self.sConsider = genSMatrix(4)
			while not checkOldGuesses(self.STries,self.sConsider):
				self.sConsider = genSMatrix(4)
			self.STries.append(self.sConsider)
			
			#Keep generating new P matrices to test
			self.pConsider = genPMatrix(8)
			while not checkOldGuesses(self.PTries,self.pConsider):
				self.pConsider = genPMatrix(8)
			self.PTries.append(self.pConsider)
			
			self.GPrimeConsider = modTwo(self.sConsider*self.G*self.pConsider)

		return True
	    
#### Hamming 16,11 Version ######
#### Created to test security of Key Cracking ####

#### Private Key H1611 ####


class privateKeyH1611:
    """Datastructure to represent our Private Key"""

    def __init__(self, S=None, P=None):
        """Initalizer that will set S,P, random if not given values"""
        # Hamming 16,11 in standard
        self.G = np.matrix([
            [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1],
            [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1],
            [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1],
            [0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1],
            [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1],
            [0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1],
            [0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1],
            [0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 0, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0]
        ], dtype=int)
        self.H = np.matrix([
            [1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 1, 1, 0, 0, 1],
            [0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 1, 1, 0, 1, 0, 1],
            [0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1, 1],
            [0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 1, 1, 1, 1, 0],
            [0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0]
        ], dtype=int)

        # Can create these from known values, otherwise random
        if S == None:
            self.S = modTwo(genSMatrix(11))
        else:
            self.S = S

        if P == None:
            self.P = modTwo(genPMatrix(16))
        else:
            self.P = P

    def printCode(self):
        """Canonical print to screen function"""
        print("S: \n" + str(self.S) + "\n")
        print("P: \n" + str(self.P) + "\n")
        print("GPrime: \n" + str(self.makeGPrime()) + "\n")

    def makeGPrime(self):
        """Returns a version of GPrime usable for calculations"""
        return modTwo(self.S*self.G*self.P)


#### Public Key H1611 ####
class publicKeyH1611:
    """Public Key Data Structure, much simplified then H8,4"""

    def __init__(self, GPrime):
        self.GPrime = GPrime

    def printCode(self):
        """Canonical print to screen"""
        print("GPrime: \n" + str(self.GPrime) + "\n")

##### Brute Forcer Based on H16,11 ####
class bruteForcerH1611():
	"""Data structure that attempts to create Private Key from Given Public Key"""
	def __init__(self,GPrime):
		
		self.attempts = 0
		
		self.GPrime = GPrime
		
		self.GPrimeConsider = 0
		self.sConsider = 0
		self.pConsider = 0
		
		self.STries = list()
		self.PTries = list()
		
		self.G = np.matrix([
		[1,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1],
		[0,1,0,0,0,0,0,0,0,0,0,0,1,0,1,1],
		[0,0,1,0,0,0,0,0,0,0,0,0,1,1,0,1],
		[0,0,0,1,0,0,0,0,0,0,1,0,0,0,1,1],
		[0,0,0,0,1,0,0,0,0,0,1,0,0,1,0,1],
		[0,0,0,0,0,1,0,0,0,0,1,0,1,0,0,1],
		[0,0,0,0,0,0,1,0,0,0,1,0,1,1,1,1],
		[0,0,0,0,0,0,0,1,0,0,1,0,1,1,0,0],
		[0,0,0,0,0,0,0,0,1,0,1,0,1,0,1,0],
		[0,0,0,0,0,0,0,0,0,1,1,0,0,1,1,0],
		[0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,0]
		], dtype=int)
		
	def printCode(self):
		"""Canonical Print self function"""
		print("Calculated GPrime:\n" + str(self.GPrimeConsider) + "\n")
		print("sM:\n" + str(self.sConsider) + "\n")
		print("pM:\n" + str(self.pConsider) + "\n")
		print("Attempts: " + str(self.attempts) + "\n")
		
	def attemptKey(self):
		"""Attempts to reconstitute S,P given GPrime (G is already known)"""
		self.attempts = 1
		
		self.sConsider = genSMatrix(11)
		self.STries.append(self.sConsider)
		
		self.pConsider = genPMatrix(16)
		self.PTries.append(self.pConsider)
		
		self.GPrimeConsider = modTwo(self.sConsider*self.G*self.pConsider)
		
		while not np.array_equal(self.GPrimeConsider.A1,self.GPrime.A1):
			self.attempts += 1
		
			self.sConsider = genSMatrix(11)
			while not checkOldGuesses(self.STries,self.sConsider):
				self.sConsider = genSMatrix(11)
			self.STries.append(self.sConsider)
			
			self.pConsider = genPMatrix(16)
			while not checkOldGuesses(self.PTries,self.pConsider):
				self.pConsider = genPMatrix(16)
			self.PTries.append(self.pConsider)
			
			self.GPrimeConsider = modTwo(self.sConsider*self.G*self.pConsider)
			
		return True

##### DNA Lookup Datastructure ###


class lookupDNA():
    """Data structure that keeps a table of DNA mappings"""

    def __init__(self, encryptFile, decryptFile):
        self.encLU = dict()
        self.decLU = dict()

        dreader = csv.reader(open(decryptFile, 'r'))
        for row in dreader:
            k, v = row
            self.decLU[k] = str(v)

        ereader = csv.reader(open(encryptFile, 'r'))
        for row in ereader:
            k, v = row
            self.encLU[k] = str(v)

    def lookDNAEncrypt(self, bstring):
        """Finds DNA sequence from 8 bits"""
        try:
            return str(self.encLU[bstring])
        except:
            return "?"

    def lookDNADecrypt(self, bstring):
        """Finds 8 bits from 8 characters of DNA"""
        try:
            return str(self.decLU[bstring])
        except:
            return "?"


if __name__ == "__main__":
    pass
