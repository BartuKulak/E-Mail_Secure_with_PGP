import myMD5
import myRSA
import myIDEA
import zipfile
import zlib
import base64
import time
import send
import getpass
def server(msg_file, IDEA_key, client_e, client_n, server_d, server_n):
    print("\n\t--PGP algorithm encryption section begins--\n")
    print("\n-Files to be encrypted:", msg_file)
    fileObject = open(msg_file, 'r')
    file_val = fileObject.read()
    print("\n-Message to be encrypted:",file_val)

    md5_val = myMD5.generate_MD5(msg_file)
    print("\n-MD5 value of file:", md5_val)

    m = int(md5_val, 16)
    signature = myRSA.RSA_encrypt(m, server_d, server_n)
    print("\n-Generating a file signature is complete")

    with open(msg_file, "rb") as f:
        raw_data = f.read()
    data = 'content=' + str(raw_data) + 'signature=' + str(signature)
    print("\n-Email data and digital signature adding is completed")

    compress_data = zlib.compress(str.encode(data), zlib.Z_BEST_COMPRESSION)
    print("\n-File compression is complete")

    my_idea = myIDEA.IDEA(key=IDEA_key)
    blocks = myIDEA.string_to_blocks(str(compress_data))
    encrypt_IDEA_words = []
    for block in blocks:
        encrypt_IDEA_words.append(my_idea.encrypt(block))
    print("\n-The file is encrypted using IDEA")

    encrypt_IDEA_key = myRSA.RSA_encrypt(IDEA_key, client_e, client_n)
    print("\n-IDEA key encrypted with RSA")

    msg = 'data='
    l = []
    for m in encrypt_IDEA_words:
        l.append(str(m))
        l.append(',')
    msg += ''.join(l)
    msg = msg + 'key=' + str(encrypt_IDEA_key)
    print("\n-Concatenate the IDEA key after RSA encryption with the IDEA encrypted data")

    base64_encode_data = base64.b64encode(msg.encode('utf-8'))
    print("\n-BASE64 encryption of the encrypted data is completed")


    print("\n-E-Mail is sending")
    sender_email = ""
    receiver_email = ""
    sender_password = ""
    sender_email = input("\nEnter your email address: ")
    sender_password = getpass.getpass("\nEnter your password: ")
    receiver_email = input("\nEnter receiver email address: ")
    message=(base64_encode_data.decode('utf-8'))
    send.sendEmail(sender_email, sender_password, receiver_email, message)
    print("\n\t--PGP algorithm encryption section ends--\n")
    
    
