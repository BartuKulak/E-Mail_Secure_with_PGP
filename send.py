from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
import os
import ssl

def sendEmail(sender_email, sender_password, receiver_email,message):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = receiver_email
    msg['Subject'] = 'Computer Networks-2 Bartu Kulak 05170000510'
    msg.attach(MIMEText(message, 'plain'))
    context = ssl.create_default_context()
    with smtplib.SMTP_SSL("smtp.gmail.com", context=context) as connection:
        connection.login(sender_email, sender_password)
        connection.sendmail(sender_email, receiver_email, msg.as_string())
        print("\n-E-mail Sent Succesfully")
