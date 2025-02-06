import imaplib
import email
import re
import codecs
import string
import hashlib
import ssl
import socket

# Step 2: Login with gmail
# create an IMAP4_SSL class instance
imap = imaplib.IMAP4_SSL("imap.gmail.com")

# login with your Gmail account credentials
username = "joecarlin30@gmail.com"
password = "xvzc uxri rdfv msvg" #should be an app password, to create one follow this link:https://support.google.com/accounts/answer/185833
imap.login(username, password)


# Step 3: Load Emails
for i in imap.list()[1]:
    l = i.decode().split(' "/" ')
    print(l[0] + " = " + l[1])