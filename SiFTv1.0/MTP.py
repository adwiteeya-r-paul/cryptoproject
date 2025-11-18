from getpass import getpass
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import PBKDF2

statefile  = 'sndstate.txt'
inputfile  = 'payload_to_send.txt'
outputfile = 'message.bin'

# TODO: read the content of the state file
with open(statefile, 'rt') as sf:
    sqn = ... # type should be integer

# read the content of the input file into payload
with open(inputfile, 'rb') as inf:
    payload = inf.read()

# TODO: compute payload_length and set authtag_length
payload_length = ...
authtag_length = ...

# set the header length to 16
#    version: 2 bytes
#    type:    1 btye
#    length:  2 btyes
#    sqn:     4 bytes
#    rnd:     7 bytes
header_length = 16

# TODO: compute message length...
msg_length = ...

# TODO: create header
header_version_field = b'\x03\x07'               # protocol version 3.7
header_type_field = b'\x01'                      # message type 1
header_length_field = ...                        # message length (encoded on 2 bytes)
header_sqn_field = ...                           # next message sequence number (encoded on 4 bytes)
header_rnd_field = Random.get_random_bytes(7)    # 7-byte long random value
header = header_version_field + \
         header_type_field + \
         header_length_field + \
         header_sqn_field + \
         header_rnd_field

# TODO: compute a salt value as the SHA256 hash of the header
hashfn = ...
hashfn.update(...)
salt = ...

# TODO: ask for a passphrase for the purpose of generating the key
password = ...

# TODO: derive a 32 bytes long AES key from the password using PBKDF2
# with the salt, iteration count 100000 and SHA256 as the hash module of HMAC
key = PBKDF2(...)

# TODO: encrypt the payload and compute the authentication tag over the header and the payload
# with AES in GCM mode using nonce = header_sqn_field + header_rnd_field
nonce = ...
AE = AES.new(...)
AE.update(...)
encrypted_payload, authtag = AE.encrypt_and_digest(...)

# TODO: write out the header, the encrypted_payload, and the authtag
with open(outputfile, 'wb') as outf:
    outf.write(...)

# save state
state = "sqn: " + str(sqn + 1)
with open(statefile, 'wt') as sf:
    sf.write(state)
