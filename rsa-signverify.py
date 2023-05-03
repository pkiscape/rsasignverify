#!/usr/bin/env python3

import argparse 
from cryptography.hazmat.primitives import serialization,hashes 
from cryptography.hazmat.primitives.asymmetric import dsa, rsa, padding

'''
usage: signverify.py [-h] [-k KEY] [-s SIGN] [-v VERIFY] [-sig SIGNATURE] [-out OUT]

A python-based RSA sign and verify tool

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Define the RSA private or public key file in PEM format
  -s SIGN, --sign SIGN  Specify file to sign using RSA private key. Uses PSS padding.
  -v VERIFY, --verify VERIFY
                        Specify message to verify using passed RSA public key
  -sig SIGNATURE, --signature SIGNATURE
                        Specify signature to verify using passed RSA public key
  -out OUT, --out OUT   Define the file in which to write the signature. Defaults to "signature.bin"

'''

def loadkey(mykey,keytype):
	'''
	Loads a given PEM-encoded private or public key. Passed private keys should not be encrypted.
	'''

	if keytype == "private":

		with open(mykey,"rb") as private_key_file:
			private_key = serialization.load_pem_private_key(private_key_file.read(),password=None)
			return private_key

	if keytype == "public":
		with open(mykey,"rb") as public_key_file:
			public_key = serialization.load_pem_public_key(public_key_file.read())
			return public_key

	else:
		print("Didnt work")


def hashmessage(message):
	'''
	Takes a hash of the message in SHA256 to be signed
	'''

	sha2digest = hashes.Hash(hashes.SHA256())
	sha2digest.update(message)
	sha2digest = sha2digest.finalize()
	print("=====Hashing file=====")
	print("String: " + sha2digest.hex())

	return sha2digest

def signmsg(myprivatekey,sha2digest):
	'''
	Signs the sha2digest with prviate key using RSA/PSS padding
	'''
	print("\n" + "=====Signing file=====")
	signature = myprivatekey.sign(
		sha2digest,
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
		hashes.SHA256()	
		)

	return signature


def verify(mypublickey,signature,sha2digest):
	'''
	Verifies the signature using given public key
	'''

	verification = mypublickey.verify(
		signature,
		sha2digest,
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),
    	hashes.SHA256()
		)
	#If the signature does not match, verify() will raise an InvalidSignature exception.

	if verification == None:
		print("Verification Successful")

def main():
	'''
	A python-based RSA sign and verify tool
	'''

	argparse_main = argparse.ArgumentParser(description="A python-based RSA sign and verify tool")
	
	argparse_main.add_argument("-k","--key", help="Define the RSA private or public key file in PEM format")
	argparse_main.add_argument("-s","--sign", help="Specify file to sign using RSA private key. Uses PSS padding.")
	argparse_main.add_argument("-v","--verify", help="Specify message to verify using passed RSA public key")
	argparse_main.add_argument("-sig","--signature", help="Specify signature to verify using passed RSA public key")
	argparse_main.add_argument("-out","--out", help="Define the file in which to write the signature. Defaults to signature.bin")
	args = argparse_main.parse_args()


	if args.key:
		if args.sign:
			myprivatekey = loadkey(args.key, keytype="private")
			if args.sign:
				with open(args.sign, "rb") as message:
					message = message.read()
					sha2digest = hashmessage(message)
					signature = signmsg(myprivatekey,sha2digest)

					print(f"Signature in bytes: {signature}" + "\n")
					print(f"Signature in a string: {bytes.hex(signature)}")

					if args.out:
						outfile = str(args.out)
						
					else:
						outfile = "signature.bin"
				
					with open(outfile, "wb") as signaturefile:
						signaturefile.write(signature)
					print(f"\nSignature written to {outfile}")


		if args.verify:
			mypublickey = loadkey(args.key,keytype="public")
			if args.verify:
				with open(args.verify, "rb") as message:
					message = message.read()
					sha2digest = hashmessage(message)

				if args.signature:
					with open (args.signature, "rb") as signedmessage:
						signedmessage = signedmessage.read()
						verifyoperation = verify(mypublickey,signedmessage,sha2digest)


if __name__ == '__main__':
	main()
