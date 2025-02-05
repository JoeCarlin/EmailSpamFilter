# importing the libraries and modules
import imaplib
import email
import re
import codecs
import string

# create an IMAP_SSl class instance
imap = imaplib.IMAP4_SSL('imap.gmail.com') # this is the server for gmail, if you are using another email provider, you can find the server address by searching for it on google, you must enable IMAP in your email settings
# login to the email account
username = 'joecarlin30@gmail.com'
password = 'xvzc uxri rdfv msvg' # this password should be an app password created in your google account settings, to do so follow this link: https://support.google.com/accounts/answer/185833
imap.login(username, password)

# use imap.list to get the list of mailboxes
for mailbox in imap.list()[1]:
    decoded_mailbox = mailbox.decode().split(' "/" ')
    print(decoded_mailbox[1])
    