from base64 import b64encode
from binascii import unhexlify

str_ = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
def __decode__(s):
    a = unhexlify(s)
    #unhexlify() returns a byte array... just something to keep in mind.
    print (a)
    b = b64encode(a)
    print (b)
    return b

__decode__(str_)