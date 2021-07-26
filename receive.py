import imaplib
import email
import re
import os
def receiveEmail(email_address, password):
    with imaplib.IMAP4_SSL("imap.gmail.com") as connection:
        connection.login(email_address, password)
        connection.select('inbox')
        _, data = connection.search(None, '(SUBJECT "Computer Networks 2")')
        message = ""
        _, data = connection.fetch(data[0].split()[-1], "(RFC822)")
        for response_part in data:
            if isinstance(response_part, tuple):
                msg = email.message_from_string(response_part[1].decode())
                message = msg.get_payload()[0].get_payload()
                break
        if not message:
            print("\n-Error, there is no received message.")
            exit(-1)
        print("\n-Decryption e-mail read")
        return (message)
