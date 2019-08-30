from base64 import b64decode
from Crypto.Cipher import AES
def AES_ECB_decrypt(ciphertext,key):
        cipher = AES.new(key,AES.MODE_ECB)
        plaintext = cipher.decrypt(ciphertext)
        return plaintext

def main():
    with open('/home/ubuntu_18_04/Documents/Cryptopals/Set1/7.txt') as input_file:
        cipher = b64decode(input_file.read())

    key = "YELLOW SUBMARINE"
    result = AES_ECB_decrypt(cipher,key)
    print(result)    
if __name__ == "__main__":
    main()