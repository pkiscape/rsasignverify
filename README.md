# rsa-signverify
A python-based RSA sign and verify tool

Requires cryptography https://pypi.org/project/cryptography/
Please ensure that you are using cryptography version 3.1 or greater

```pip3 install cryptography```

```
usage: rsa-signverify [-h] [-k KEY] [-s SIGN] [-v VERIFY] [-sig SIGNATURE] [-out OUT]
optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     Define the RSA private or public key file in PEM format
  -s SIGN, --sign SIGN  Specify file to sign using RSA private key. Uses PSS padding.
  -v VERIFY, --verify VERIFY
                        Specify message to verify using passed RSA public key
  -sig SIGNATURE, --signature SIGNATURE
                        Specify signature to verify using passed RSA public key
  -out OUT, --out OUT   Define the file in which to write the signature. Defaults to "signature.bin"
```
## Examples
**====Signing====**

Generic signing using your RSA private key. It uses PSS padding (Probabilistic signature scheme). It saves the signature as signature.bin

```rsa-signverify.py  -k private_key.pem -s data.png``` 

Same as above, but define a file to write the signature to a custom file.

```rsa-signverify.py -k private_key.pem -s data.png -out data.png.sig```

**====Verifying signatures====**

When verifying signatures, pass the public key (public_key.pem) along with the actual message (data.png) and the signature (data.png.sig)

```rsa-signverify.py -k public_key.pem -v data.png -sig data.png.sig```

"Verification Successful" will appear when the signature and message can be verified with the public key

If the signature does not match, verify() will raise an InvalidSignature exception.

<hr>

**If you don't have a keypair to start with:**

**Generate private key:**

```openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048.key```

**Then you can derive public key from private key:**

```openssl rsa -in rsa2048.key -pubout -out rsa2048.pub```
