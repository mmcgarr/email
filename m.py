#!/usr/bin/python
import smtplib
import string
import sys
import imaplib
import getpass
import email
import base64
from OpenSSL import crypto, SSL 
from OpenSSL.crypto import FILETYPE_PEM, load_privatekey
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from M2Crypto import RSA, X509 
import Crypto.Hash.SHA256 as SHA256

CA_CERT_FILE = "CACert.crt"
CA_KEY_FILE = "CAPrivateKey.key"
Sender_CERT_FILE = "SenderCert.crt"
Sender_KEY_FILE = "SenderPrivateKey.key"
REC_CERT_FILE = "ReceiverCert.crt"
REC_KEY_FILE = "ReceiverPrivateKey.key"


encodedLength = 0

def main():
  my_addr = raw_input("Login email: ")
  password = getpass.getpass("Password: ", sys.stderr)
  create_self_signed_cert(CA_CERT_FILE, CA_KEY_FILE)
  create_self_signed_cert(Sender_CERT_FILE, Sender_KEY_FILE)
  create_self_signed_cert(REC_CERT_FILE, REC_KEY_FILE)

  sendMail(my_addr, password)
  getMail(my_addr, password)

def sendMail(my_addr, password):
  SUBJECT = "Test email from Python"
  TO = raw_input("To: ") 
  FROM = my_addr 
  text = "blah blah blah"
  text = SignAndEncrypt(text, True, True)
  BODY = string.join((
    "From: %s" % FROM,
    "To: %s" % TO,
    "Subject: %s" % SUBJECT ,
    "",
    text
    ), "\r\n")
  server = smtplib.SMTP("smtp.gmail.com", 587)
  print "Connecting to SMTP Server..."
  server.ehlo();
  server.starttls();
  server.ehlo();
  server.login(FROM, password)
  print "Logging in..."
  server.sendmail(FROM, TO, BODY)
  server.quit()
  print "Email sent."

def getMail(my_addr, password):
  print "Connecting to IMAP server..."
  mail = imaplib.IMAP4_SSL('imap.gmail.com')
  print "Logging in..."
  mail.login(my_addr, password)
  mail.list()
  # Out: list of "folders" aka labels in gmail.
  mail.select("inbox") # connect to inbox.
  result, data = mail.search(None, "ALL")

  ids = data[0] # data is a list.
  id_list = ids.split() # ids is a space separated string
  latest_email_id = id_list[-1] # get the latest

  print "Fetching latest email..."
  result, data = mail.fetch(latest_email_id, "(RFC822)") # Get the email

  print decrypt(email.message_from_string(data[0][1]).get_payload() )

def create_self_signed_cert(CERT_FILE, KEY_FILE):

  # create a key pair
  k = crypto.PKey()
  k.generate_key(crypto.TYPE_RSA, 2048)

  # create a self-signed cert
  cert = crypto.X509()
  cert.get_subject().C = "UK"
  cert.get_subject().ST = "London"
  cert.get_subject().L = "London"
  cert.get_subject().O = "Dummy Company Ltd"
  cert.get_subject().OU = "Dummy Company Ltd"
  cert.get_subject().CN = gethostname()
  cert.set_serial_number(1000)
  cert.gmtime_adj_notBefore(0)
  cert.gmtime_adj_notAfter(10*365*24*60*60)

  # if this is the CA cert we are creating use it's own key to sign this cert.
  if CERT_FILE == "CACert.crt":
    cert.set_issuer(cert.get_subject())
    cert.sign(k, 'sha1')
  else:
    #otherwise open the file to find the ca's key to sign the file.
    capr = open(CA_KEY_FILE)
    ca_priv_key = load_privatekey(FILETYPE_PEM, capr.read())
    cert.sign(ca_priv_key, 'sha1')
  cert.set_pubkey(k)

  #Write both the cert and the key to files.
  open(CERT_FILE, "wt").write(
      crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
  open(KEY_FILE, "wt").write(
      crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

  # Method to sign and encrypt a message. 
# doEncrypt and doSign are used to choose if the message is to be encrypted and signed. 
def SignAndEncrypt(plaintext, doEncrypt, doSign):
  f = open(REC_CERT_FILE)
  rec_cert_buffer = f.read()
  f.close()
  rec_cert = X509.load_cert_string(rec_cert_buffer, X509.FORMAT_PEM) 
  rec_pub_key = rec_cert.get_pubkey()
  rec_rsa_key = rec_pub_key.get_rsa() 

  if doEncrypt:
    print "Encrypting..."
    cipher = base64.b64encode(rec_rsa_key.public_encrypt(plaintext, RSA.pkcs1_padding))
    indicateEnc = "--RSA ENCRYPTED MESSAGE--\n"
  else:
    cipher = plaintext
    indicateEnc = ""

  if doSign:
    print "Signing..."
    signiture = sign(cipher)

    cipher = indicateEnc + cipher + '\n\n--digsig\n' + signiture 
  else:
    cipher = indicateEnc + cipher

  print "Cipher: " + cipher
  return cipher

def sign(cipher):
  SenderPrivateKey = RSA.load_key(Sender_KEY_FILE)
  hash = SHA256.new(cipher).digest() 
  return base64.b64encode(SenderPrivateKey.sign(hash))

def verify(ciphertext, signiture):
  f = open(Sender_CERT_FILE)
  Sender_cert_buffer = f.read()
  f.close()

  sender_cert = X509.load_cert_string(Sender_cert_buffer, X509.FORMAT_PEM)
  Sender_pub_key = sender_cert.get_pubkey()
  Sender_rsa_key = Sender_pub_key.get_rsa() 

  hash2 = SHA256.new(ciphertext).digest()
  assert Sender_rsa_key.verify(hash2, signiture)

def decrypt(cipher):
  ReadRSA = RSA.load_key(REC_KEY_FILE)
  index = cipher.find("--digsig")

  if cipher.find("--RSA ENCRYPTED MESSAGE--") != -1:
    isEnc = True
    startingIndex = 27
  else:
    startingIndex = 0
    isEnc = False 

  plaintext = cipher

  # if the message is signed.
  if index != -1:
    signiture = cipher[index+10:]
    cipher = cipher[startingIndex:index-4]

    startingIndex = 0
    print "Cipher: " + cipher
    print "Signiture: " + signiture

    signiture = base64.b64decode(signiture)

    print "Verifiing Signiture..."
    verify(cipher, signiture)
    print "Verified."
    plaintext = cipher

  # if the message is encrypted	
  if isEnc:
    cipher = base64.b64decode(cipher[startingIndex:])
    try:
      print "Decrypting Message..."
      plaintext = "Message:\n	" + ReadRSA.private_decrypt (cipher, RSA.pkcs1_padding)
    except:
      print "Error: wrong key?"
      plaintext = ""

  return plaintext

if __name__ == "__main__":
  main()
