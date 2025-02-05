# EmailSpamFilter

## Project Overview

The goal of this project is to develop an effective email spam filter specifically tailored for advertisement emails. Utilizing your own email account, primarily focusing on platforms such as Gmail due to its extensive spam collection, you will gather examples of spam emails to construct and train the spam filter.

---

## Steps to Implement the Spam Filter

### Step 1: Import Libraries and Necessary Packages

```python
import imaplib
import email
import re
import codecs
import string
import hashlib
import ssl
import socket

# create an IMAP4_SSL class instance
imap = imaplib.IMAP4_SSL("imap.gmail.com")

# login with your Gmail account credentials
username = "youremail@gmail.com"
password = "AppPassword" #should be an app password, to create one follow this link:https://support.google.com/accounts/answer/185833
imap.login(username, password)


Step #3: Load Emails

for i in imap.list()[1]:
    l = i.decode().split(' "/" ')
    print(l[0] + " = " + l[1])
