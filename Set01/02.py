import binascii
str_ = binascii.unhexlify(b"1c0111001f010100061a024b53535009181c").decode("ASCII")
key_ = binascii.unhexlify(b"686974207468652062756c6c277320657965").decode("ASCII")

def Fixed_XOR(data,key):
    #convert str_decoded into a list of char pair tuples
    # go through eacz tuple, converting them to ASCII codes (ord())
    # Perform XOR with ord(key)
    # Then Convert back to plain text using ASCII (chr)
    # merge as string
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip (data,key))

print (Fixed_XOR(str_,key_))