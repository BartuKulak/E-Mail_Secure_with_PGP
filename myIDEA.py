def addition(a, b):
    """ Addition modulo 2^16
    :param a: <int>
    :param b: <int>
    :return: result: <int>
    """

    result = (a + b) % 0x10000
    assert 0 <= result <= 0xFFFF

    return result


def multiplication(a, b):
    """ Multiplication modulo 2^16 + 1 ,
    where tha all-zero word (0x0000) in inputs is interpreted as 2^16,
    and 2^16 in output is interpreted as the all-zero word (0x0000)
    :param a: <int>
    :param b: <int>
    :return: result: <int>
    """

    # Assert statements are a convenient way to insert debugging
    # 'assert expression' is equivalent to :
    # if __debug__:
    #   if not expression: raise Assertion Error
    assert 0 <= a <= 0xFFFF  # FFFF = 65535
    assert 0 <= b <= 0xFFFF

    # Preventing entropy destruction and insure reversibility
    if a == 0:
        a = 0x10000  # 65536 = 2^16
    if b == 0:
        b = 0x10000

    result = (a * b) % 0x10001

    if result == 0x10000:
        result = 0

    assert 0 <= result <= 0xFFFF
    return result


def mul_inv(a):
    """
    :type a: int
    """
    if a == 0:
        a = 0x10000

    result = pow(a, 0x10001 - 2, 0x10001)
    return result


#########################
#                       #
#     IDEA CLASSES      #
#                       #
#########################

class IDEA(object):
    """
    This class is responsible for managing the encryption.
    It will generate subkeys and encrypt/decrypt the data.
    """

    def __init__(self, key=0x2BD6459F82C5B300952C49104881FF48, keylength=128):
        self.keylength = keylength
        self.subkeys = [None]
        self.generate_subkeys(key)

    def generate_subkeys(self, key):
        """ IDEA operates with 52 subkeys.
        The first 8 sub-keys are extracted directly from the key, with K1 from the first round being the lower 16 bits.
        Further groups of 8 keys are created by rotating the main key left 25 bits between each group of 8.
        :param key: <int> key in hexadecimals
        """
        # assert 0 <= key < (1 << self.keylength) # debug
        modulo = 1 << self.keylength  # 0x100000000000000000000000000000000 (129 bits)

        sub_keys = []
        for i in range(52):
            sub_keys.append((key >> ((self.keylength - 16) - 16 * (i % (self.keylength // 16)))) % 0x10000)  # slicing the key into X 16bits long parts
            if i % int(self.keylength // 16) == (self.keylength // 16) - 1:  # keylength = 128, i = {7, 15, 23, 31, 39, 47}
                # x << y basically returns x with the bits shifted to the left by y places, BUT new bits on the right-hand-side are replaced by zeros.
                # To obtain a clean permutation, we simply do (x << y) OR (x >> (len(x)-y))
                key = ((key << 25) | (key >> (self.keylength - 25))) % modulo

        # Each round uses 6 16-bit sub-keys, while the half-round uses 4,
        # Putting subkeys into tuples should ease the encryption.
        keys = []
        for i in range(9):  # 8.5 round => 9 tuples
            round_keys = sub_keys[6 * i: 6 * (i + 1)]
            keys.append(tuple(round_keys))
        self.subkeys = tuple(keys)

    def encrypt(self, plaintext):
        """ IDEA Encryption
        :param plaintext:
        :return: cipher: <int> encrypted text
        """
        B1 = (plaintext >> 48) & 0xFFFF  # 0xFFFF masc
        B2 = (plaintext >> 32) & 0xFFFF
        B3 = (plaintext >> 16) & 0xFFFF
        B4 = plaintext & 0xFFFF

        for i in range(8):
            K = self.subkeys[i]  # gathering necessary subkeys
            B1 = multiplication(B1, K[0])  # 1
            B2 = addition(B2, K[1])  # 2
            B3 = addition(B3, K[2])  # 3
            B4 = multiplication(B4, K[3])  # 4

            T1 = B1 ^ B3  # 5
            T2 = B2 ^ B4  # 6

            T1 = multiplication(T1, K[4])  # 7
            T2 = addition(T2, T1)  # 8
            T2 = multiplication(T2, K[5])  # 9
            T1 = addition(T1, T2)  # 10

            B1 = B1 ^ T2  # 11
            B3 = B3 ^ T2  # 12
            B2 = B2 ^ T1  # 13
            B4 = B4 ^ T1  # 14

            B2, B3 = B3, B2  # 15

        # NB : B2 and B3 are not permuted in the last round !!!
        # That is why we re-invert them
        B2, B3 = B3, B2

        # Half Round
        K = self.subkeys[8]
        B1 = multiplication(B1, K[0])
        B2 = addition(B2, K[1])
        B3 = addition(B3, K[2])
        B4 = multiplication(B4, K[3])

        cipher = (B1 << 48) | (B2 << 32) | (B3 << 16) | B4
        return cipher

    def generate_d_subkeys(self):
        """ Generate decrypting subkeys
        :return: tuple(d_keys): <tuple(int)>
        """
        d_sub_keys = []
        K = self.subkeys[8]
        d_sub_keys.append(mul_inv(K[0]))
        d_sub_keys.append(-K[1] % 0x10000)
        d_sub_keys.append(-K[2] % 0x10000)
        d_sub_keys.append(mul_inv(K[3]))

        for i in reversed(range(8)):
            K = self.subkeys[i]
            d_sub_keys.append(K[4])  # KD(5) = K(47)
            d_sub_keys.append(K[5])  # KD(6) = K(48)
            # noinspection PyTypeChecker
            d_sub_keys.append(mul_inv(K[0]))  # KD(7) = 1/K(43)
            d_sub_keys.append(-K[2] % 0x10000)  # KD(8) = -K(45)
            d_sub_keys.append(-K[1] % 0x10000)  # KD(9) = -K(44)
            # noinspection PyTypeChecker
            d_sub_keys.append(mul_inv(K[3]))  # KD(10) = 1/K(46)

        d_keys = []
        for i in range(9):  # 8.5 round => 9 tuples
            round_keys = d_sub_keys[6 * i: 6 * (i + 1)]
            d_keys.append(tuple(round_keys))

        return tuple(d_keys)

    def decrypt(self, ciphertext):
        """
        Decryption works like encryption, but the order of the round keys is inverted, and the subkeys for the odd rounds are inversed.
        For instance, the values of subkeys K1–K4 are replaced by the inverse of K49–K52 for the respective group operation,
        K5 and K6 of each group should be replaced by K47 and K48 for decryption.
        :param ciphertext: <int>
        :return: plaintext: <int>
        """
        d_subkeys = self.generate_d_subkeys()

        B1 = (ciphertext >> 48) & 0xFFFF  # 0xFFFF masc
        B2 = (ciphertext >> 32) & 0xFFFF
        B3 = (ciphertext >> 16) & 0xFFFF
        B4 = ciphertext & 0xFFFF

        for i in range(8):
            KD = d_subkeys[i]  # gathering necessary subkeys
            B1 = multiplication(B1, KD[0])  # 1
            B2 = addition(B2, KD[1])  # 2
            B3 = addition(B3, KD[2])  # 3
            B4 = multiplication(B4, KD[3])  # 4

            T1 = B1 ^ B3  # 5
            T2 = B2 ^ B4  # 6

            T1 = multiplication(T1, KD[4])  # 7
            T2 = addition(T2, T1)  # 8
            T2 = multiplication(T2, KD[5])  # 9
            T1 = addition(T1, T2)  # 10

            B1 = B1 ^ T2  # 11
            B3 = B3 ^ T2  # 12
            B2 = B2 ^ T1  # 13
            B4 = B4 ^ T1  # 14

            B2, B3 = B3, B2  # 15

        # Half Round
        KD = d_subkeys[8]
        B1 = multiplication(B1, KD[0])
        B2 = addition(B2, KD[1])
        B3 = addition(B3, KD[2])
        B4 = multiplication(B4, KD[3])

        # Permuting after
        B2, B3 = B3, B2

        plaintext = (B1 << 48) | (B2 << 32) | (B3 << 16) | B4
        return plaintext

    def make_64bit_block(c_bytes):
        """Turn 1 to 8 separate bytes into a 64 bit block"""
        assert len(c_bytes) <= 8
        c_bytes = list(c_bytes)
        # If we have less than 8 bytes, pad it out to 8 bytes using 0x10[00]...
        if len(c_bytes) < 8:
            c_bytes.extend([0x10])
        while len(c_bytes) < 8:
            c_bytes.extend([0x00])

        return sum([(c_bytes[i] << (8 * (7 - i))) for i in range(8)])

    def create_sub_blocks(block):
        """Break a 64-bit block into four 16-bit words"""
        mask = 0xFFFF
        return [Word((block >> 16 * (3 - i)) & mask) for i in range(4)]


    def blocks_to_string(blocks):
        """Convert a list of unencrypted 64-bit blocks to a string"""
        return ''.join([bytearray([block >> (8 * (7 - i)) & 0xFF
                                   for i in range(8)]).decode('utf-8')
                        for block in blocks])
def make_64bit_block(c_bytes):
    """Turn 1 to 8 separate bytes into a 64 bit block"""
    assert len(c_bytes) <= 8
    c_bytes = list(c_bytes)
    # If we have less than 8 bytes, pad it out to 8 bytes using 0x10[00]...
    if len(c_bytes) < 8:
        c_bytes.extend([0x10])
    while len(c_bytes) < 8:
        c_bytes.extend([0x00])
    return sum([(c_bytes[i] << (8 * (7 - i))) for i in range(8)])

def string_to_blocks(message):
    """Convert a message into unencrypted 64-bit blocks"""
    msg_bytes = message.encode('utf-8')
    # break the message into 64-bit blocks
    blocks = [IDEA.make_64bit_block(msg_bytes[idx:idx + 8])
                for idx in range(0, len(message), 8)]
    return blocks
def blocks_to_string(blocks):
    """Convert a list of unencrypted 64-bit blocks to a string"""
    return ''.join([bytearray([block >> (8 * (7 - i)) & 0xFF
                                   for i in range(8)]).decode('utf-8')
                        for block in blocks])