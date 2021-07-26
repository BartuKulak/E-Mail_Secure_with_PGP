import base64
import myRSA
import myIDEA
import myMD5
import zlib
import codecs
import receive
import getpass
def IDEA_data_process(msg):
    msg = str(msg)
    str_data = msg.split("data=")[1]
    data, key = str_data.split('key=')[0], msg.split('key=')[1][:-1]
    return data, key

def data_process(msg):
    msg = str(msg)
    tmp = msg.split('content=', 1)[1]
    content, signature = tmp.rsplit('signature=', 1)[0], tmp.rsplit('signature=', 1)[1][:-1]
    return content, signature

def client(client_n, client_d, server_e, server_n):
    print("\n\t--PGP algorithm decryption section begins--\n")
    email = ""
    password = ""
    email = input("\nEnter your email address: ")
    password = getpass.getpass("\nEnter your password: ")
    received_email = receive.receiveEmail(email, password)

    msg = base64.b64decode(received_email)
    print("\n-BASE64 decoding completed")

    encrypt_IDEA_data, encrypt_IDEA_key = IDEA_data_process(msg)
    print("\n-Separating the RSA-encrypted IDEA key from the IDEA-encrypted data in the encrypted data is done separately from the IDEA-encrypted data")
 
    decrypt_IDEA_key = myRSA.RSA_encrypt(int(encrypt_IDEA_key), client_d, client_n)
    print("\n-The IDEA key K is:", hex(decrypt_IDEA_key))

    blocks = encrypt_IDEA_data.split(',')[:-1]
    my_idea = myIDEA.IDEA(key=decrypt_IDEA_key)
    decrypt_IDEA_words = []
    for block in blocks:
        decrypt_IDEA_words.append(my_idea.decrypt(int(block)))
    msg = myIDEA.blocks_to_string(decrypt_IDEA_words)
    msg = bytes(msg[2:-1], encoding = 'utf-8')
    original = codecs.escape_decode(msg, 'hex-escape')
    print("\n-Decrypting the IDEA-encrypted data using the IDEA key K is complete")

    uncompress_data = zlib.decompress(original[0])
    print("\n-The decrypted data is decompressed")

    content, signature = data_process(uncompress_data)
    content = bytes(content[2:-4], encoding = 'utf-8')
    print("\n-Separate the message data from the digital signature")

    signature_decrypt = myRSA.RSA_encrypt(int(signature), server_e, server_n)
    print("\n-The decrypted signature is:", hex(signature_decrypt))

    message=content.decode('utf-8')
    md5_val = myMD5.generate_MD5('file.txt')
    print("\n-The MD5 value of the file is:", hex(int(md5_val,16)))
    if hex(int(md5_val,16)) == hex(signature_decrypt):
        print('\n-The verification is successful.')
    else:
        print('\n-Verification failed!!!!!')
        
    print("\n-Decrypted message:",message)
    print("\n\t--PGP algorithm decryption section ends--\n")
    
