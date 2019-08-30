# IF YOU CAN'T DO THIS, ALSO TRY TO DETECT SIMPLER ONES LIKE ROT13 CIPHER
# AES ECB IS STATELESS AND DETERMINISTIC, MEANING IT'LL CREATE THE SAME CIPHERTEXT FOR THE SAME KEY AND DATA , EVERYTIME.
# READ MORE AT https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Electronic_Codebook_(ECB)
# IT IS CLEARLY MENTIONED IN THE PROBLEM THE LENGTH OF KEY IS 16 BYTES LONG, LIKE "YELLOW SUBMARINE"(I REALLY DO LIKE IT NOW).
def detective(ciphertext,block_size):
        blocks = [ciphertext[i:i+block_size] for i in range(0,len(ciphertext),block_size)]
        nos_of_repetition= len(blocks)-len(set(blocks))
        result = {
                'ciphertext':ciphertext,
                'repetition':nos_of_repetition
        }
def main ():
    ciphers = open('/home/ubuntu_18_04/Documents/Cryptopals/Set1/4.txt').read().splitlines()
    for hexstring in ciphers:
        ciphertext = bytes.fromhex(hexstring)
    block_size = 16
    repetition = [detective(cipher, block_size)for cipher in ciphertext]    
    most_repetetion = sorted(repetition,key=lambda x: x['repetition'], reverse=True)[0]
    print("REPEATING BLOCKS: {}".format(most_repetetion['repetition']))
    print("CIPHERTEXT: {}".format(most_repetetion['ciphertext']))
if __name__ == '__main__':
    main()