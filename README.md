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
pip install africastalking
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
pip install bcrypt
```
Add below fucntion to functions.py - Used for encrypting/Decrypting
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


def hash_verify(password,  hashed_password):
    bytes = password.encode('utf-8')
    result = bcrypt.checkpw(bytes, hashed_password.encode())
    print(result)
    return result


#hash_verify("kenya1234", "$2b$12$LyTDdwhw5GHR6ILxTSrCfu69/x4xpihitQ3QZXUHOXa7YRQtg2FcO")
# Output
# Returns True/False
```





