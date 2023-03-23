from doctest import master
import menu
import requests
from backports.pbkdf2 import pbkdf2_hmac
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Util import Padding
from Cryptodome.Hash import HMAC
from time import sleep


# url = "http://127.0.0.1:8000/"
url = "http://54.85.90.130/"
token = None
master_key = None

def throw_error():
    ...

s_box = [
            [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
            [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
            [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
            [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
            [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
            [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
            [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
            [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
            [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
            [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
            [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
            [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
            [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
            [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
            [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
            [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
        ]
inv_s_box = [
        [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
        [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
        [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
        [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
        [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
        [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
        [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
        [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
        [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
        [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
        [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
        [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
        [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
        [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
        [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]

class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token
    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r

def Login():
    global master_key;
    global token;
    email = input("Enter Email:")
    password = input("Enter password:")
    resp = requests.get(url + "users/get_salt",params={"email":email})
    if resp.status_code == 404:
        print("User does not exist")
        exit()
    salt = bytes.fromhex(resp.text.strip('"'))
    master_and_derived_key = pbkdf2_hmac("sha256","{}:{}".format(email,password).encode(),salt,50000,32)
    derived_key = master_and_derived_key[:len(master_and_derived_key)//2]
    master_key_enc_key = master_and_derived_key[len(master_and_derived_key)//2:]
    crypt = AES.new(master_key_enc_key,AES.MODE_CBC)

    resp = requests.post(url + "users/login",json={"email":email,"derived_key":derived_key.hex()})
    if resp.status_code in [404,403]:
        print("Invalid credentials")
        exit()
    token = resp.json()["access_token"]
    encrypted_master_key = resp.json()["encrypted_master_password"]
    master_key = crypt.decrypt(bytes.fromhex(encrypted_master_key))
    print("Login successful")
    sleep(2)


def Register():
    global master_key;
    global token;
    name = input("Enter name:")
    email = input("Enter Email:")
    password = input("Enter password:")
    salt = get_random_bytes(16)
    master_key = get_random_bytes(32)
    master_and_derived_key = pbkdf2_hmac("sha256","{}:{}".format(email,password).encode(),salt,50000,32)
    derived_key = master_and_derived_key[:len(master_and_derived_key)//2]
    master_key_enc_key = master_and_derived_key[len(master_and_derived_key)//2:]
    crypt = AES.new(master_key_enc_key,AES.MODE_CBC)
    encrypted_master_key = crypt.encrypt(master_key)

    resp = requests.put(url + "users/register",json={"email":email,"derived_key":derived_key.hex(),"name":name,"encrypted_master_password":encrypted_master_key.hex(),"salt":salt.hex()})

    if resp.status_code != 200:
        print("Invalid input")
        print(resp.json())
        exit()
    print("Successfully created user")
    exit()

def Quit():
    exit()


def addRoundKey(data, keySchedule):
    # XOR each byte of the data with the corresponding byte of the key schedule
    new_data = bytes(data[i] ^ keySchedule[i] for i in range(len(data)))

    return new_data

def generateRoundKeys(key):
    # Define the number of rounds for AES-256
    num_rounds = 14

    # Create a list to store the round keys
    round_keys = []

    # Convert the input key into a list of 32-bit words
    words = [key[i:i+4] for i in range(0, len(key), 4)]

    # Add the initial key as the first round key
    round_keys.append(key)

    # Perform key schedule operations to generate the remaining round keys
    for i in range(1, num_rounds + 1):
        # Rotate the bytes of the previous round key
        rot_word = words[-1][1:] + words[-1][:1]

        # Apply the S-box substitution to the bytes of the rotated word
        sub_word = bytes(s_box[b] for b in rot_word)

        # XOR the first byte of the previous round key with a round constant
        round_const = bytes([r_con[i]])
        xor_word = bytes(sub_word[0] ^ round_const[0]) + sub_word[1:]

        # Generate the next word of the key schedule by XORing the
        # corresponding words from the previous round key and the new word
        next_word = bytes(words[4 * (i-1) + j] ^ xor_word[j] for j in range(4))

        # Add the new round key to the list of round keys
        round_keys.append(bytes(next_word))

        # Add the new word to the list of words
        words += [next_word]

    return round_keys

def inverseSubBytes(data):
    # Compute the inverse substitution using the inverse s-box
    inv_data = []
    for byte in data:
        inv_byte = inv_s_box[byte]
        inv_data.append(inv_byte)
    return bytes(inv_data)

def subBytes(state):
    for i in range(len(state)):
        for j in range(len(state[i])):
            # Get the value in the (i,j) position of the state
            value = state[i][j]

            # Get the corresponding value from the S-box table
            substituted_value = s_box[value >> 4][value & 0x0f]

            # Replace the value in the state with the substituted value
            state[i][j] = substituted_value
    return state

def shiftRows(state):
    for i in range(1, len(state)):
        # Rotate the ith row i number of steps to the left
        state[i] = state[i][i:] + state[i][:i]
    return state

def permutation(data):
    # Define the permutation table (IP table)
    perm_table  = [
        242, 226, 210, 194, 178, 162, 146, 130,
        114, 98, 82, 66, 50, 34, 18, 2,
        243, 227, 211, 195, 179, 163, 147, 131,
        115, 99, 83, 67, 51, 35, 19, 3,
        244, 228, 212, 196, 180, 164, 148, 132,
        116, 100, 84, 68, 52, 36, 20, 4,
        245, 229, 213, 197, 181, 165, 149, 133,
        117, 101, 85, 69, 53, 37, 21, 5,
        246, 230, 214, 198, 182, 166, 150, 134,
        118, 102, 86, 70, 54, 38, 22, 6,
        247, 231, 215, 199, 183, 167, 151, 135,
        119, 103, 87, 71, 55, 39, 23, 7,
        248, 232, 216, 200, 184, 168, 152, 136,
        120, 104, 88, 72, 56, 40, 24, 8,
        249, 233, 217, 201, 185, 169, 153, 137,
        121, 105, 89, 73, 57, 41, 25, 9,
        250, 234, 218, 202, 186, 170, 154, 138,
        122, 106, 90, 74, 58, 42, 26, 10,
        251, 235, 219, 203, 187, 171, 155, 139,
        123, 107, 91, 75, 59, 43, 27, 11,
        252, 236, 220, 204, 188, 172, 156, 140,
        124, 108, 92, 76, 60, 44, 28, 12,
        253, 237, 221, 205, 189, 173, 157, 141,
        125, 109, 93, 77, 61, 45, 29, 13,
        254, 238, 222, 206, 190, 174, 158, 142,
        126, 110, 94, 78, 62, 46, 30, 14,
        255, 239, 223, 207, 191, 175, 159, 143,
        127, 111, 95, 79, 63, 47, 31, 15
    ]

    bin_str = ''.join(format(byte, '08b') for byte in data)

    # Permute the bits according to the table
    permuted_str = ''.join(bin_str[i - 1] for i in perm_table)

    # Convert the permuted binary string back into bytes
    permuted_data = bytes(int(permuted_str[i:i+8], 2) for i in range(0, len(permuted_str), 8))

    return permuted_data

def inverseShiftRows(data):
    # Inverse shift the rows of the input data
    inv_data = bytearray(data)
    for i in range(4):
        # Compute the number of shifts for the current row
        num_shifts = i
        # Inverse shift the current row by the number of shifts
        for j in range(4):
            inv_data[i + 4*j] = data[i + 4*((j - num_shifts) % 4)]
    return bytes(inv_data)

def inversePermutation(data):
    permuteTable =  [
        242, 226, 210, 194, 178, 162, 146, 130,
        114, 98, 82, 66, 50, 34, 18, 2,
        243, 227, 211, 195, 179, 163, 147, 131,
        115, 99, 83, 67, 51, 35, 19, 3,
        244, 228, 212, 196, 180, 164, 148, 132,
        116, 100, 84, 68, 52, 36, 20, 4,
        245, 229, 213, 197, 181, 165, 149, 133,
        117, 101, 85, 69, 53, 37, 21, 5,
        246, 230, 214, 198, 182, 166, 150, 134,
        118, 102, 86, 70, 54, 38, 22, 6,
        247, 231, 215, 199, 183, 167, 151, 135,
        119, 103, 87, 71, 55, 39, 23, 7,
        248, 232, 216, 200, 184, 168, 152, 136,
        120, 104, 88, 72, 56, 40, 24, 8,
        249, 233, 217, 201, 185, 169, 153, 137,
        121, 105, 89, 73, 57, 41, 25, 9,
        250, 234, 218, 202, 186, 170, 154, 138,
        122, 106, 90, 74, 58, 42, 26, 10,
        251, 235, 219, 203, 187, 171, 155, 139,
        123, 107, 91, 75, 59, 43, 27, 11,
        252, 236, 220, 204, 188, 172, 156, 140,
        124, 108, 92, 76, 60, 44, 28, 12,
        253, 237, 221, 205, 189, 173, 157, 141,
        125, 109, 93, 77, 61, 45, 29, 13,
        254, 238, 222, 206, 190, 174, 158, 142,
        126, 110, 94, 78, 62, 46, 30, 14,
        255, 239, 223, 207, 191, 175, 159, 143,
        127, 111, 95, 79, 63, 47, 31, 15
    ]
    # Inverse permute the input data

    inv_data = bytearray(len(data))
    for i in range(len(data)):
        # Compute the index of the current bit in the output
        out_idx = permuteTable[i]
        # Compute the byte and bit index of the current bit in the input
        in_byte_idx, in_bit_idx = divmod(out_idx, 8)
        # Compute the mask for the current bit in the input
        mask = 1 << (7 - in_bit_idx)
        # Check if the current bit is set in the input byte
        if data[in_byte_idx] & mask:
            # Set the current bit in the output byte
            out_mask = 1 << (7 - i % 8)
            inv_data[i // 8] |= out_mask
    return bytes(inv_data)


def ModifiedAES(data, key):
    # Generate round keys
    keySchedule = generateRoundKeys(key)

    # Initial round
    data = addRoundKey(data, keySchedule[0])

    # Main rounds
    for i in range(1, 10):
        data = subBytes(data, s_box)
        data = shiftRows(data)
        data = permutation(data)
        data = addRoundKey(data, keySchedule[i])

    # Final round
    data = subBytes(data, s_box)
    data = shiftRows(data)
    data = addRoundKey(data, keySchedule[10])

    return data



def UploadFile():
    if token == None:
        print("Please login")
        sleep(3)
        return
    file_path = input("Enter file location:")
    with open(file_path,"rb") as file:
        file_name = file_path.split("/")[-1]
        file_key = get_random_bytes(32)
        crypt = AES.new(file_key,AES.MODE_ECB)
        key_crypt = AES.new(master_key,AES.MODE_ECB)
        try:
            _encr = ModifiedAES(file_key, master_key)
        except:
            # _encr= AES.new(file_key, master_key)
            throw_error()
        encrypted_file_key = key_crypt.encrypt(file_key)
        encrypted_data = crypt.encrypt(Padding.pad(file.read(),16))
        hmac = HMAC.new(master_key,encrypted_data).hexdigest()
        temp = open("/tmp/" + file_name,"wb")
        temp.write(encrypted_data)
        temp.close()
        temp = open("/tmp/" + file_name,"rb")
        resp = requests.put(url + "files/upload",auth=BearerAuth(token),files={"encrypted_file":temp},data={"encrypted_file_key":encrypted_file_key.hex(),"hmac":hmac})
        temp.close()
        if resp.status_code != 200:
            print(resp)
            print("Something went wrong")
            exit()
        file_id = resp.json()["file_id"]
        print("File_id:",file_id)
        sleep(10)

def GetFileById():
    if token == None:
        print("Please login")
        sleep(3)
        return
    file_id = input("Enter file_id:")
    resp = requests.get(url + "files/{}".format(file_id),auth=BearerAuth(token))
    if resp.json().get("status") == "error":
        print("Invalid file id")
        sleep(3)
        return
    file_name = resp.json()["file_name"]
    encrypted_file_key = bytes.fromhex(resp.json()["encrypted_file_key"])
    dirty_hmac = bytes.fromhex(resp.json()["hmac"])
    key_crypt = AES.new(master_key,AES.MODE_ECB)
    file_key = key_crypt.decrypt(encrypted_file_key)
    resp = requests.get(url + "files/{}/download".format(file_id),auth=BearerAuth(token))
    crypt = AES.new(file_key,AES.MODE_ECB)
    print("Decrypting {}...".format(file_name))
    with open(file_name,"wb") as file:
        hmac = HMAC.new(master_key,resp.content)
        try:
            hmac.verify(dirty_hmac)
        except:
            print("INVALID HMAC ,FILE HAS BEEN MODIFIED")
            exit()
        file_data = Padding.unpad(crypt.decrypt(resp.content),16)
        file.write(file_data)
    print("Data written to {}".format(file_name))
    sleep(5)

print("Welcome to Encrypt EveryWhere Client")
splash_options = [("Login",Login),
            ("Register",Register),
            ("Upload",UploadFile),
            ("Download",GetFileById),
            ("Quit",Quit)]
splash_menu = menu.Menu(title="Welcome to Encrypt EveryWhere Client",options=splash_options)
splash_menu.open()
