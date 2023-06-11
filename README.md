# MediLab API
This Mobile System to be developed will aim to improve services in a Medical
Laboratory where patients are sent/ Go to take Lab test. The System will
allow patients to request for Lab test for themselves or Dependants. The
Patient can request for tests to be done at home(Send Nurse-For elderly) or
in the hospital. Applications will have an admin dashboard to receive
Requested Lab tests, Allocate to specific Nurses/Technicians who will
perform the action of getting the specimen and take for testing.
PLEASE FOLLOW STEP BY STEP!


This is the Application Programming Interface(API) for this Application.

# Part 1.
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
h) Check Password Validity
This function checks password validity
```
import re
def passwordValidity(password):
    # define a function to check password strength
    if (len(password) < 8):
        return "inValid Password less than 8"

    elif not re.search("[a-z]", password):
        return "inValid Password no small letter"

    elif not re.search("[A-Z]", password):
        return "inValid Password no caps"

    elif not re.search("[0-9]", password):
        return "inValid Password no numbers"

    elif not re.search("[_@$]", password):
        return "inValid Password no symbol"
    else:
        return True

#print(passwordValidity("jNjkbj334kffdghfdh"))
```

i) Below Function checks if phone number meets a given Format, Uses Regex
```
import re
def check_phone(phone):
    regex = "^\+254\d{9}"
    if not re.match(regex, phone)  or len(phone) !=13:
        print("Phone Not Ok")
        return False
    else:
        print("Phone Ok")
        return True

#check_phone("+254729225710")
```

###End of Step 1

# Part 2 - API Development
## Set Up.
a) Create two files one named app.py, the other named views.py.
The views.py will contain all the API Codes/Resource implemetation, These include but not limited to POST, GET, PUT, DELETE, PATCH etc.
b) The app.py will include the API endpoints Configurations, it will act as the main file 
Install Flask and flask_restful
```
pip3 install flask
pip3 install flask_restful
```
Inside app.py, please add below code.

```
from flask import *
from flask_restful import Api
app = Flask(__name__)

api=Api(app)

# To configure Endpoints/Routes here
# ...

if __name__ == '__main__':
    app.run(debug=True)
    
```

c) Inside views.py
Add below imports, and create the Member Class
```
import pymysql
import pymysql.cursors
from flask_restful import Resource
from flask import *
from functions import *

# Add Members class, and include two methods POST - member_signup, GET - member_signin
class MemberSignup(Resource):
    def post(self):
        # Get data from Client
        data = request.json
        username = data['surname']
        others = data['others']
        gender = data['gender']
        email = data['email']
        phone = data['phone']
        dob = data['dob']
        password = data['password']
        location_id = data['location_id']
        # Check password validity
        response = passwordValidity(password)
        # Check if password validity is True
        if response == True:
            # Connect to DB
            connection = pymysql.connect(host='localhost', user='root', password='',
                                         database='MediLab')
            cursor = connection.cursor()
            sql = "insert into members (surname, others, gender, email, phone, dob, password, location_id) 
            values(%s, %s, %s, %s, %s, %s, %s, %s)"
            try:
                cursor.execute(sql, (username, others, gender, email, phone, dob, hash_password(password), location_id))
                connection.commit()
                # Send SMS after successful registration
                send_sms(phone, "Registration Successful.")

                return jsonify({'message': 'POST SUCCESS. RECORD SAVED'})
            except:
                connection.rollback()
                return jsonify({'message': 'POST FAILED. RECORD NOT SAVED'})
        else:
            return jsonify({'message': response})
            
            
 class MemberSignin(Resource):        
        def get(self):
                # Get request form Client
                data = request.json
                email = data['email']
                password =  data['password']

                # Connect to DB
                connection = pymysql.connect(host='localhost', user='root', password='',
                                         database='MediLab')

                # Check if email exists
                sql = "select * from members where email = %s"
                cursor = connection.cursor(pymysql.cursors.DictCursor)
                cursor.execute(sql, (email))
                if cursor.rowcount == 0:
                    return jsonify({'message': 'Email does not Exist!'})
                else:
                    # If email Exists, get its Hashed password on that row retrieved
                    row = cursor.fetchone()
                    hashed_password = row['password']
                    # verify the hash and the password provided
                    status = hash_verify(password, hashed_password)
                    # Do they Match with Hash?, then loggin is successful
                    if status == True:
                        return jsonify({'message': 'Logged Successful'})
                    # They do not match
                    elif status == False:
                        return jsonify({'message': 'Logged Not Successful'})
                    else:
                        return jsonify({'message': 'Something went wrong'})

```
Now add the Two Classes(Resources) in your app.py
```
from flask import *
from flask_restful import Api
app = Flask(__name__)

api=Api(app)

# Add the Classes and configure the Endpoints
from views import SignUp, SignIn
api.add_resource(MemberSignup, '/api/member_signup')
api.add_resource(MemberSignin, '/api/member_signin')

if __name__ == '__main__':
    app.run(debug=True)

```

Post Man test Sign Up
![image](https://github.com/modcomlearning/MediLab/assets/66998462/d2f7185c-32a7-467f-acf5-d7d382ffbe25)

Post Man test Sign In
![image](https://github.com/modcomlearning/MediLab/assets/66998462/bf5c759d-ecc0-4fcf-abe5-8fa190aa0735)


ENd Part 2

# Part 3
In this Part we will Add 3 Classes for MemberProfile, AddDependant, ViewDependant
**a)** In views.py add below class named (MemberProfile) which allows us to provide a member_id and it returns details of that member, Is simple terms, Profile is specific member information.
```
class MemberProfile(Resource):
    def post(self):
        json = request.json
        member_id = json['member_id']
        sql = "select * from members where member_id = %s"
        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='medilab')

        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql, member_id)
        count = cursor.rowcount
        if count == 0:
            return jsonify({'message': 'Member does Not exist'})
        else:
            member = cursor.fetchone()
            return jsonify({'message': member})
 ```
 
 Update Your app.py File , Please import and add the MemberProfile Resource.
 ```
 #...
from views.views import MemberSignUp,MemberSignin, MemberProfile
api.add_resource(MemberSignUp, '/api/member_signup')
api.add_resource(MemberSignin, '/api/member_signin')
api.add_resource(MemberProfile, '/api/member_profile')
#...
 ```
 Run the App and test in Postman, Add a new Request, Below POST request shows the details of a member_id = 5
![image](https://github.com/modcomlearning/MediLab/assets/66998462/6417b950-9d50-423a-958b-4c87af033250)


 
 **b)** in views.py, add another  class named AddDependant, This class will help us Add a Dependant given a Member Id

 ```
 # Add Dependant.
class AddDependant(Resource):
    def post(self):
        # Connect to MySQL
        json = request.json
        member_id = json['member_id']
        surname = json['surname']
        others = json['others']
        dob = json['dob']

        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='medilab')
        cursor = connection.cursor()
        # Insert Data
        sql = ''' Insert into dependants(member_id,surname, others, dob)
          values(%s, %s, %s, %s) '''
        # Provide Data
        data = (member_id, surname, others, dob)
        try:
            cursor.execute(sql, data)
            connection.commit()
            return jsonify({'message': 'Dependant Added'})
        except:
            connection.rollback()
            return jsonify({'message': 'Failed. Try Again'})
 ```
 
 Update Your app.py, please import and add the AddDependant Resource.
 ```
 # ...
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant
api.add_resource(MemberSignUp, '/api/member_signup')
api.add_resource(MemberSignin, '/api/member_signin')
api.add_resource(MemberProfile, '/api/member_profile')
api.add_resource(AddDependant, '/api/add_dependant')
# ...
 ```
 Run the App and test in Postman, Add a new Request.
![image](https://github.com/modcomlearning/MediLab/assets/66998462/adcae53d-688b-4858-bf4f-55eb82ee8612)
 
 
 **c)** The Next class will help us view dependants for a given Member, How do we do that, In views.py we create a class named ViewDependants, In this class we will provide the member ID and look into dpendants table  and find the dependants belonging to that member ID, That means each member will view theor own dependants.
So, In views.py add below class.
```
class ViewDependants(Resource):
    def post(self):
        json = request.json
        member_id = json['member_id']
        sql = "select * from dependants where member_id = %s"
        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='medilab')

        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql, member_id)
        count = cursor.rowcount
        if count == 0:
            return jsonify({'message': 'Member does Not exist'})
        else:
            dependants = cursor.fetchall()
            return jsonify(dependants)
        # {}   - Means Object in JSON, comes with key - value
        # []   - Means a JSON Array
        # [ {}, {} ]  - JSON Array - with JSON Objects
```

Update Your app.py, please import and add the AddDependant Resource.
 ```
 # ...
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant, ViewDependants
api.add_resource(MemberSignUp, '/api/member_signup')
api.add_resource(MemberSignin, '/api/member_signin')
api.add_resource(MemberProfile, '/api/member_profile')
api.add_resource(AddDependant, '/api/add_dependant')
api.add_resource(ViewDependants, '/api/view_dependants')
# ...
 ```
 Run the App and test in Postman, Add a new Request, Below Post request show the dependants of a given member_id = 4
![image](https://github.com/modcomlearning/MediLab/assets/66998462/97f6ee92-e06a-4319-acdc-9f258b28af21)


# Part 4: Adding a JWT Token
Check https://jwt.io/
In this Part, we look at JWT tokens which provide Token Authentication features and provides a secure access to Our API.
Check https://jwt.io/
Step 1
Install JWT Extended
```
pip3 install flask_jwt_extended
```
Step 2,
In this example we will have two Tokens, access token and refresh tokens , the difference is they expire at different times,
We will make;
  1. access token expire within a shortest time(can be used in authemtication most secure endpoints i.e Payments).
  2. refresh token expire in longest time, can be used in less secure endpoints

Next, Add below in your **app.py** File, The can be added Just below    ...    app = Flask(__name__)
```
from datetime import timedelta
from flask_jwt_extended import JWTManager
# # Set up JWT
app.secret_key = "hfjdfhgjkdfhgjkdf865785"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)
```
Step 3
In views.py, Import JWT Extended Packages.
```
# import JWT Packages
from flask_jwt_extended import create_access_token, jwt_required, create_refresh_token
```

Step 4
In this Step update your Login done earlier in Step 2, On the Login we will only Update where the Password validation returns 
True, See an updated Login. Updated code is 0n line 625 - 631. That is Generated JWT Token upon successful Login.
```
class MemberSignin(Resource):
    def post(self):
        json = request.json
        surname = json['surname']
        password = json['password']
        # The user  enters a Plain Text Email
        sql = "select * from members where surname = %s"
        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='MediLab')

        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql, surname)
        count = cursor.rowcount
        if count == 0:
            return jsonify({'message': 'User does Not exist'})
        else:
            # user Exist
            member = cursor.fetchone()
            hashed_password = member['password']  # This Password is hashed
            # Jane provided a Plain password
            if hash_verify(password, hashed_password):
                # TODO JSON WEB Tokens
                access_token = create_access_token(identity=surname, fresh=True)
                refresh_token = create_refresh_token(surname)
                return jsonify({
                           'access_token': access_token,
                           'refresh_token': refresh_token,
                           'member': member
                       })
                       # END
            else:
                return jsonify({'message': 'Login Failed'})
                
```

Test the Member Login endpoint in POSTMAN, Below we  see a JWT access token/Refresh Toen has been generated























