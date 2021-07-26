from client import *
from server import *
import random
from myRSA import *
if __name__ == '__main__':
    # Randomly generate IDEA keys
    IDEA_key = random.getrandbits(128)

    # Generate 1024-bit server and client RSA public and private keys
    server_p, server_q, server_n, server_e, server_d = generate_RSA_key()
    client_p, client_q, client_n, client_e, client_d = generate_RSA_key()

    # Original file
    source_file = 'file.txt'
    # Server encryption
    server(source_file, IDEA_key, client_e, client_n, server_d, server_n)
    # Client decryption
    client( client_n, client_d, server_e, server_n)
