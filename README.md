# MediLab API
This Mobile System to be developed will aim to improve services in a Medical
Laboratory where patients are sent/ Go to take Lab test. The System will
allow patients to request for Lab test for themselves or Dependants. The
Patient can request for tests to be done at home(Send Nurse-For elderly) or
in the hospital. Applications will have an admin dashboard to receive
Requested Lab tests, Allocate to specific Nurses/Technicians who will
perform the action of getting the specimen and take for testing.


This is the Application Programming Interface(API) for this Application.

### Step 1.
Create a File named functions.py in your working Folder, in this file we will put neccessary functions to be used in our application. i.e Encryption, Send SMS, Randomize, Hashing, Send Email, PDF etc, These are general functions that any application will need.
Add below functions in functions.py
a) Send SMS function.
Install AFricas talking Package 
```
pip3 install africastalking
```
Read more here https://africastalking.com/

Add this Function
```
# sending an sms
import africastalking
africastalking.initialize(
    username="joe2022",
    api_key="aab3047eb9ccfb3973f928d4ebdead9e60beb936b4d2838f7725c9cc165f0c8a"
    #justpaste.it/1nua8
)
sms = africastalking.SMS
def send_sms(phone, message):
    recipients = [phone]
    sender = "AFRICASTKNG"
    try:
        response = sms.send(message, recipients)
        print(response)
    except Exception as error:
        print("Error is ", error)

# Test
#send_sms("+254729225710", "This is test message on Fleet.")
```

b) Generating Random Numbers.
Below functions generated Random Numbers of N Characters, Add it to function.py
```
def gen_random(N):
    import string
    import random
    
    # using random.choices()
    # generating random strings
    res = ''.join(random.choices(string.digits, k=N))
    # print result
    print("The generated random string : " + str(res))
    return str(res)
    
# Test    
#gen_random(N=4)

```
c) Hashing Algorithms - this is used to Hash Passwords for security purposes.
Install bcrypt

```
pip3 install bcrypt
```
Add below function to functions.py - Used for Hashing
```

import bcrypt
def hash_password(password):
    bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)
    print("Bytes ", bytes)
    print("Salt ", salt)
    print("Hashed password ", hash.decode())
    return hash.decode()
    
# Test
#hash_password("kenya1234")
# Output
# $2b$12$LyTDdwhw5GHR6ILxTSrCfu69/x4xpihitQ3QZXUHOXa7YRQtg2FcO
```
Add below function to functions.py - Used for Verify Hash

```
def hash_verify(password,  hashed_password):
    bytes = password.encode('utf-8')
    result = bcrypt.checkpw(bytes, hashed_password.encode())
    print(result)
    return result


#hash_verify("kenya1234", "$2b$12$LyTDdwhw5GHR6ILxTSrCfu69/x4xpihitQ3QZXUHOXa7YRQtg2FcO")
# Output
# Returns True/False
```
d) Add below functions used for Encryption/Decryption
Install cryptography
```
pip3 install cryptography
```
Add below fucntion to functions.py
```
# generates Encryption Key
from cryptography.fernet import  Fernet
def gen_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)
# Test
#gen_key()
```
Load Key Function Below
```
def load_key():
    return open("key.key", "rb").read()

# Test
#print(load_key())
```
Encrypt data.
```
def encrypt(data):
    key = load_key()
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode())
    print("Plain ", data)
    print("Encrypted ", encrypted_data.decode())
# Test
#encrypt("+254729225710")
# Output
# gAAAAABjLX8d8JAsCS9ipJ8mO44Px4hb6GgfydOllU7P1JJqHWTQXEXchS-CMqsE2sSz2mDhrlGDjmmCYFCn4Em7X7F6nHVBTQ==
```
Decrypt data
```
def decrypt(encrypted_data):
    key = load_key()
    f = Fernet(key)
    decrypted_data = f.decrypt(encrypted_data)
    print("Decrypted data ", decrypted_data.decode())
    return decrypted_data.decode()
# Test - Provide the Encrypted
#decrypt("gAAAAABjIY3vZqXEHBV9DIvizYUfsA6uPxx1pT16_OyopLYIAg4x52wUMwVWhRS2_IgVcQfKKZbWPRWmrcfJ15Nu3zj7rMdwWw==")
# Output
# +254729225710
```
e) Sending an Email
```
def send_email(email, message):
    import smtplib
    # creates SMTP session
    s = smtplib.SMTP('smtp.gmail.com', 587)
    # start TLS for security
    s.starttls()
    # Authentication
    s.login("modcomlearning@gmail.com", "your password")
    # sending the mail
    s.sendmail("modcomlearning@gmail.com", email, message)
    # terminating the session
    s.quit()
    
# Test
#send_email("johndoe@gmail.com", "Test Email")
```

f) Lipa na Mpesa
This function will be used to Integrate Lipa Na Mpesa.
Install requests
```
pip3 install requests
```
For more on MPESA API check https://developer.safaricom.co.ke/

Add below function to functions.py
```
import requests
import base64
import datetime
from requests.auth import HTTPBasicAuth

# In this fucntion we provide phone(used to pay), amount to be paid and invoice no being paid for.
def mpesa_payment(amount, phone, invoice_no):
        # GENERATING THE ACCESS TOKEN
        consumer_key = "GTWADFxIpUfDoNikNGqq1C3023evM6UH"
        consumer_secret = "amFbAoUByPV2rM5A"

        api_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"  # AUTH URL
        r = requests.get(api_URL, auth=HTTPBasicAuth(consumer_key, consumer_secret))

        data = r.json()
        access_token = "Bearer" + ' ' + data['access_token']

        #  GETTING THE PASSWORD
        timestamp = datetime.datetime.today().strftime('%Y%m%d%H%M%S')
        passkey = 'bfb279f9aa9bdbcf158e97dd71a467cd2e0c893059b10f78e6b72ada1ed2c919'
        business_short_code = "174379"
        data = business_short_code + passkey + timestamp
        encoded = base64.b64encode(data.encode())
        password = encoded.decode('utf-8')

        # BODY OR PAYLOAD
        payload = {
            "BusinessShortCode": "174379",
            "Password": "{}".format(password),
            "Timestamp": "{}".format(timestamp),
            "TransactionType": "CustomerPayBillOnline",
            "Amount": amount,  # use 1 when testing
            "PartyA": phone,  # change to your number
            "PartyB": "174379",
            "PhoneNumber": phone,
            "CallBackURL": "https://modcom.co.ke/job/confirmation.php",
            "AccountReference": "account",
            "TransactionDesc": "account"
        }

        # POPULAING THE HTTP HEADER
        headers = {
            "Authorization": access_token,
            "Content-Type": "application/json"
        }

        url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"  # C2B URL

        response = requests.post(url, json=payload, headers=headers)
        print(response.text)
# Test
mpesa_payment("2", "254729225710", "NCV003")
```
g) Generate PDF
This functions is used to generate PDFs.
Add it to functions.py
```
def gen_pdf():
    # Python program to create
    # a pdf file
    from fpdf import FPDF
    # save FPDF() class into a
    # variable pdf
    pdf = FPDF()
    # Add a page
    pdf.add_page()
    # set style and size of font
    # that you want in the pdf
    pdf.set_font("Arial", size=15)
    # create a cell
    pdf.cell(200, 10, txt="ModcomInstitute of tech",
             ln=1, align='L')
    # add another cell
    pdf.cell(200, 10, txt="A Computer Science portal for geeks.",
             ln=2, align='C')
    # save the pdf with name .pdf
    pdf.output("cv.pdf")

# Test
#gen_pdf()
```

###End of Step 1

# Step 2 - API Development






























