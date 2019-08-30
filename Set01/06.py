from base64 import b64decode

# THIS WAS HARD!!!!! MAJORLY BECAUSE OF MY CONFUSION IN HAMMING CODE AND HAMMING DISTANCE
# HAMMING CODE: https://en.wikipedia.org/wiki/Hamming_code 
# HAMMING DISTANCE (THIS ONE SHOWS CHARACTERS AS DIFFERING BYTES): https://en.wikipedia.org/wiki/Hamming_distance#Examples
# WE ARE CALCULATING THE HAMMING DISTANCE IN BITS. NOT CHARACTERS, NOT BYTES.....
# HOPE THAT SAVES YOU SOME TROUBLE...
def calculate_hamming_distance(str1,str2):
    """Returns the Hamming distance, give 2 inputs of two **byte** strings, Please test with byte arrays too"""
    hamming_distance = 0 #Initialize hamming distance counter
    byte1 = [byte for byte in str1] #Takeone byte from str1 and str2
    byte2 = [byte for byte in str2] 
    xor_bytes= [b1 ^ b2 for b1,b2 in zip(byte1,byte2)] #perform a xor inorder to find the changed bits
    for byte in xor_bytes:
        hamming_distance += sum([1 for bit in bin(byte) if bit == '1']) # Add 1 if  the bit is 1 for bit in byte...
    return(hamming_distance)

def get_english_score(input_bytes):
    """Compares each input byte to a character frequency 
    chart and returns the score of a message based on the
    relative frequency the characters occur in the English
    language.
    """

    # More information https://en.wikipedia.org/wiki/Letter_frequency
    # Assign a rating to each letter,
    # We use this word rating to scan for frequency of characters...
    # we judge wheter the input is in english or not by comparing the frequencies
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])

def single_char_xor(input_bytes, char_value):
    """Returns the result of each byte being XOR'd with a single value.
    """
    output_bytes = b'' #Initialize a empty byte string
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value]) # store the Xor'd value of byte^char_value in output_byte
    return output_bytes

def bruteforce_single_char_xor(ciphertext):
    """Performs a singlechar xor for each possible value(0,255), and
    assigns a score based on character frequency. Returns the result
    with the highest score.
    """
    potential_messages = [] #Inititalize the list for potential messages...
    for key_value in range(256): #range is 256 cause the extended ASCII chart contains 255 characters 
        message = single_char_xor(ciphertext, key_value) 
        score = get_english_score(message)
        data = {
            'message': message,
            'score': score,
            'key': key_value
            }
        potential_messages.append(data) #add list elements to the potential messages lists
    return sorted(potential_messages, key=lambda x: x['score'], reverse=True)[0] #return sorted messages....

def repeated_key_XOR(m_bytes,key):
    """Decrypts the message that was once XOR'd against a repeating key (habits maketh the man :P )"""
    output_bytes = b'' # Initialize the bytes string
    index = 0 # initialize the index at 0 
    for byte in m_bytes:
        output_bytes += bytes([byte ^ key[index]])
        if (index + 1) == len(key):
            index = 0 #add nothing if the value of the index+1 is equal to the length of key
        else:
            index += 1 #add 1 if value of the index is not equal to length.
    return output_bytes

def breaking_repeated_keyXOR(ciphertext):
    """Attempts to break XOR with an repeated key, Attempts... that's all we can do..."""
    average_distances_ = []

    # Taking the key size from suggested range(2,40)
    for keysize in range(2,41):
        distances = []
        blocks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)] # Break the ciphertext into blocks the length of the keysize
        
        while True:
            try:
                block_1 = blocks[0]
                block_2 = blocks[1]
                distance = calculate_hamming_distance(block_1, block_2)
                distances.append(distance/keysize)
                del blocks[0]
                del blocks[1]
            except Exception as e:
                break
        result = {
            'key': keysize,
            'avg distance': sum(distances) / len(distances)
            }
        average_distances_.append(result)
    possible_key_lengths = sorted(average_distances_, key=lambda x: x['avg distance'])[0]
    possible_plaintext = []
    key = b''
    possible_key_length = possible_key_lengths['key']
    for i in range(possible_key_length):
        block = b''
        for j in range(i, len(ciphertext), possible_key_length):
            block += bytes([ciphertext[j]])
        key += bytes([bruteforce_single_char_xor(block)['key']]) 
    possible_plaintext.append((repeated_key_XOR(ciphertext, key), key)) 
    return max(possible_plaintext, key=lambda x: get_english_score(x[0]))

def main():
    with open('/home/ubuntu_18_04/Documents/Cryptopals/Set1/6.txt')as input_file:# 1: Read the file contents as input,
        ciphers = b64decode(input_file.read()) #Base64 decode lines form the input
    result, key = breaking_repeated_keyXOR(ciphers)
    print("Key: {} Message: {} ".format(key, result))
if __name__ == "__main__":
    main()