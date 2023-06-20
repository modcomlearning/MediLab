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

Check this Link for the APIs Endpoints t be created.

https://coding.co.ke/advanced/api/API%20Design.pdf

## Set Up.
a) Structure: Create two files one named app.py, create a Folder named **views** and place a file named views.py inside.

The **views.py** will contain all the API Codes/Resource implemetation, These include but not limited to POST, GET, PUT, DELETE, PATCH etc.
b) The **app.py** will include the API endpoints Configurations, it will act as the main file 
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
In this Part, we look at JWT tokens which provide Token Authentication features and provides a secure access to Our API.
Check https://jwt.io/

Step 1
Install JWT Extended
```
pip3 install flask_jwt_extended
```
Step 2.

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
True, See an updated Login. Code to Update on Signin is between **TODO** Comment. 
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
                # TODO
                access_token = create_access_token(identity=surname, fresh=True)
                refresh_token = create_refresh_token(surname)
                return jsonify({
                           'access_token': access_token,
                           'refresh_token': refresh_token,
                           'member': member
                       })
                 # TODO
            else:
                return jsonify({'message': 'Login Failed'})
                
```

Test the Member Login endpoint in POSTMAN, Below we  see a JWT access token/Refresh Toen has been generated.
This is a POST Request
![image](https://github.com/modcomlearning/MediLab/assets/66998462/27622fab-5f48-43f5-9fda-61a6cc0bc264)

# Part 5: 
### Create More endpoints - Labs, Labtests, Booking, Payments.
In this part we will extend our Apis Base and add more endpoints to support our application.

Step 1

In views.py, Add below Class named - Laboratories- Returns a Lists of Laboratories. 
NB: You must have some Labs in your laboratories table. 
```
class Laboratories(Resource):
    def get(self):
        sql = "select * from laboratories"
        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='MediLab')

        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql)
        count = cursor.rowcount
        if count == 0:
            return jsonify({'message': 'No Laboratories Listed'})
        else:
            laboratories = cursor.fetchall()
            return jsonify(laboratories)
```

In app.py, Configure the Endpoint.
```
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant, ViewDependants, Laboratories
# ....
api.add_resource(Laboratories, '/api/laboratories')
```
Test in Postman as a new Request, below we see some laboratories returned. This is a GET Request.
![image](https://github.com/modcomlearning/MediLab/assets/66998462/44e2e395-c8d8-475e-9cfd-df7d51080a03)


Step 2.

In views.py, add a LabTests class, This class will return lab test given the laboratory ID. Make sure you have some lab tests in your lab_tests table.

Add below code in views.py
```
class LabTests(Resource):
    def post(self):
        json = request.json
        lab_id = json['lab_id']
        sql = "select * from lab_tests where lab_id = %s"
        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='MediLab')

        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql, lab_id)
        count = cursor.rowcount
        if count == 0:
            return jsonify({'message': 'No Lab tests'})
        else:
            lab_tests = cursor.fetchall()
            return jsonify(lab_tests)
  ```
  
  
In app.py, Configure the Endpoint.
```
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant, ViewDependants, Laboratories, LabTests
# ....
api.add_resource(LabTests, '/api/lab_tests')
```

Test in Postman, Here we return lab tests belonging to Laboratory with ID 2(Lancet). This is a POST Request
![image](https://github.com/modcomlearning/MediLab/assets/66998462/03f4c48f-9eec-4e4f-aee8-95c6e1824038)

Step 3.

We create a Make booking Class, This is done since we have a members, dependants, laboratories and lab tests APIs,
Its now possible to trigger a make booking API.

in views.py, add below MakeBooking API Class
```
class MakeBooking(Resource):
    def post(self):
        # Connect to MySQL
        json = request.json
        member_id = json['member_id']
        booked_for = json['booked_for']
        dependant_id = json['dependant_id']
        test_id = json['test_id']
        appointment_date = json['appointment_date']
        appointment_time = json['appointment_time']
        where_taken = json['where_taken']
        latitude = json['latitude']
        longitude = json['longitude']
        lab_id = json['lab_id']
        invoice_no = json['invoice_no']


        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='MediLab')
        cursor = connection.cursor()
        # Insert Data
        sql = ''' Insert into bookings(member_id,booked_for, dependant_id,test_id, appointment_date,
         appointment_time, where_taken, latitude,longitude, lab_id, invoice_no )
          values(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) '''
        # Provide Data
        data = (member_id,booked_for, dependant_id,test_id, appointment_date,
         appointment_time, where_taken, latitude,longitude, lab_id, invoice_no)
        try:
            cursor.execute(sql, data)
            connection.commit()
            # Select from members to find Phone No
            sql = '''select * from members where member_id = %s'''
            cursor = connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(sql, member_id)
            member = cursor.fetchone()
            # Get phone No
            phone = member['phone']
            # Send SMS to above phone number . NB: decrypt phone number!
            send_sms(decrypt(phone), "Booking Scheduled on {} at {} : Invoice No. {} "
            .format(appointment_date, appointment_time, invoice_no))
            return jsonify({'message': 'Booking Received. '})
        except:
            connection.rollback()
            return jsonify({'message': 'Failed. Try Again'})
 
```

  
In app.py, Configure the Endpoint.
```
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant, ViewDependants, Laboratories, LabTests, MakeBooking
# ....
api.add_resource(MakeBooking, '/api/make_booking')
```

Test in Postman. This is a POST Request
PayLoad.
```
  {
    "member_id": 11,
    "booked_for": "Dependant",
    "dependant_id": "2",
    "test_id": 1,
    "appointment_date": "2023-01-08",
    "appointment_time": "10:00:00",
    "where_taken": "Home",
    "latitude": "1.456789",
    "longitude": "32.3456789o",
    "lab_id": 1,
    "invoice_no": "5454545"
}
```
![image](https://github.com/modcomlearning/MediLab/assets/66998462/e447b70f-7ef4-4932-99af-4c800847de40)

Step 4.

This Endpoint will view member bookings made using the Member ID which is a Foreign key in booking table.

In views.py, add below code.
```
class MyBookings(Resource):
    def get(self):
        json = request.json
        member_id = json['member_id']
        sql = "select * from bookings where member_id = %s"
        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='MediLab')

        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql, member_id)
        count = cursor.rowcount
        if count == 0:
            return jsonify({'message': 'No Bookings'})
        else:
            bookings = cursor.fetchall()
            
            import json
            # date and time was not convertible to JSON, Hence the use of json.dumps, json.loads
            # We pass the bookings to json.dumps
            jsonStr = json.dumps(bookings, indent=1, sort_keys=True, default=str)
            # Then covert json string to json object
            return json.loads(jsonStr)
           

```
In app.py, Configure the Endpoint.
```
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant, ViewDependants, Laboratories, LabTests, MakeBooking, MyBookings
# ....
api.add_resource(MyBookings, '/api/mybookings')
```

Test In Postman. This is a Get Request.
![image](https://github.com/modcomlearning/MediLab/assets/66998462/62ecd2b6-cc91-457c-821b-e14cc0ee87f0)

Step 5
This Endpoints is used to Make Payment for a given Endpoint Using MPESA API Function.

In views.py, add below code.
```
class MakePayment(Resource):
    def post(self):
        json = request.json
        phone = json['phone']
        amount = json['amount']
        invoice_no = json['invoice_no']
        # Access Mpesa Functions locatated in functions.py
        mpesa_payment(amount, phone, invoice_no)
        return jsonify({'message': 'Sent - Complete Payment on Your Phone.'})
 ```
 
 In app.py, Configure the Endpoint.
```
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant, ViewDependants, Laboratories, LabTests, MakeBooking, MyBookings, MakePayment
# ....
api.add_resource(MakePayment, '/api/make_payment')
```
Test in Postman This is a POST Request.
![image](https://github.com/modcomlearning/MediLab/assets/66998462/4429252a-3f50-42e3-8603-2f3cfb21256b)

### End of Part 5

# Part 6
In this part we will create APIs to be used by the Admin Dashboard where the laboratories will be able to upload Lab test, add nurses, view bookings etc.
in views folder create a file named views_dashboard.py, 
```
# Import Required modules
import pymysql
from flask_restful import *
from flask import *
from functions import *
import pymysql.cursors

# import JWT Packages
from flask_jwt_extended import create_access_token, jwt_required, create_refresh_token
# Create a Class for sign Up
class LabSignup(Resource):
    def post(self):
        json = request.json
        lab_name = json['lab_name']
        permit_id = json['permit_id']
        email = json['email']
        phone = json['phone']
        password = json['password']

        # Check Password
        response = passwordValidity(password)
        if response:
            if check_phone(phone):
                connection = pymysql.connect(host='localhost',
                                                user='root',
                                                password='',
                                                database='medilab')
                cursor = connection.cursor()
                sql = '''insert into laboratories(lab_name, permit_id, email,
                phone, password) values(%s, %s, %s, %s, %s)'''
                
                # Data
                data = (lab_name, permit_id, email, encrypt(phone), 
                        hash_password(password))
                try:
                    cursor.execute(sql, data)
                    connection.commit()
                    code = gen_random(4)
                    send_sms(phone, '''Thank you for Joining MediLab. 
                    Your Secret No: {}. Do not share.'''.format(code))
                    return jsonify({'message': 'Thank you for Joining MediLab'})
                except:
                    connection.rollback()
                    return jsonify({'message': 'Not OK'})

            else:
                return jsonify({'message': 'Invalid Phone ENter +254'})
        else :
            return jsonify({'message': response})
        
```

Add blow class for sign in 
```
class LabSignin(Resource):
    def post(self):
        json = request.json
        email = json['email']
        password = json['password']

        sql = "select * from laboratories where email = %s"
        connection = pymysql.connect(host='localhost',
                                                user='root',
                                                password='',
                                                database='medilab')
          
        cursor = connection.cursor(pymysql.cursors.DictCursor)
        cursor.execute(sql, email)
        count = cursor.rowcount
        if count == 0:
            return jsonify({'message': 'Email does Not exist'})
        else:
            lab = cursor.fetchone()
            hashed_password = lab['password']
            # Verify
            if hash_verify(password, hashed_password):
                # TODO JSON WEB Tokens
                       access_token = create_access_token(identity=email,
                                                          fresh=True)
                       refresh_token = create_refresh_token(email)

                       return jsonify({'message': lab, 
                                       'access_token': access_token,
                                       'refresh_token':refresh_token})            
            else:
                       return jsonify({'message': 'Login Failed'})
            

```

Next add below class for Viewing the Lab Profile
```
class LabProfile(Resource):
     @jwt_required(refresh=True) # Refresh Token
     def post(self):
          json = request.json
          lab_id = json['lab_id']
          sql = "select * from laboratories where lab_id = %s"
          connection = pymysql.connect(host='localhost',
                                                user='root',
                                                password='',
                                                database='medilab')
          
          cursor = connection.cursor(pymysql.cursors.DictCursor)
          cursor.execute(sql, lab_id)
          count = cursor.rowcount
          if count == 0:
               return jsonify({'message': 'Lab does Not exist'})
          else:
               lab = cursor.fetchone()
               return jsonify({'message': lab})
          
```
This class will be used to Add Lab tests
```
class AddLabTests(Resource):
     @jwt_required(refresh=True) # Refresh Token
     def post(self):
          json = request.json
          lab_id = json['lab_id']
          test_name = json['test_name']
          test_description  =  json['test_description']
          test_cost = json['test_cost']
          test_discount = json['test_discount']
          availability = json['availability']
          more_info = json['more_info']

          connection = pymysql.connect(host='localhost',
                                                user='root',
                                                password='',
                                                database='medilab')
          cursor = connection.cursor()

          sql = '''insert into lab_tests(lab_id, test_name, test_description,
           test_cost, test_discount, availability, more_info) 
           values(%s,%s,%s,%s,%s,%s,%s)'''
          
          # data 
          data = (lab_id, test_name, test_description,
          test_cost, test_discount, availability, more_info)
          
          try:
            cursor.execute(sql, data)
            connection.commit()
            return jsonify({'message': 'Test Added'})
          except:
               connection.rollback()
               return jsonify({'message': 'Test Not Added'})

```

Next, we create a class to help the Labs access their saved lab tests

```
class ViewLabTests(Resource):
     @jwt_required(refresh=True) # Refresh Token
     def post(self):
          json = request.json
          lab_id = json['lab_id']
          sql = "select * from lab_tests where lab_id = %s"
          connection = pymysql.connect(host='localhost',
                                                user='root',
                                                password='',
                                                database='medilab')
          
          cursor = connection.cursor(pymysql.cursors.DictCursor)
          cursor.execute(sql, lab_id)
          count = cursor.rowcount
          if count == 0:
               return jsonify({'message': 'No Tests Found'})
          else:
               tests = cursor.fetchall()
               return jsonify(tests)

```

In this class, we get all bookings made, we select using a specific lab ID, it returns all bookings for that specific Lab
```
class ViewLabBookings(Resource):
     @jwt_required(refresh=True) # Refresh Token
     def post(self):
          json = request.json
          lab_id = json['lab_id']
          sql = "select * from bookings where lab_id = %s"
          connection = pymysql.connect(host='localhost',
                                                user='root',
                                                password='',
                                                database='medilab')
          
          cursor = connection.cursor(pymysql.cursors.DictCursor)
          cursor.execute(sql, lab_id)
          count = cursor.rowcount
          if count == 0:
               return jsonify({'message': 'No Bookings'})
          else:
               bookings = cursor.fetchall()
               for booking in bookings:
                    member_id = booking['member_id']
                    sql = ''' select * from members where member_id=%s'''
                    cursor = connection.cursor(pymysql.cursors.DictCursor)
                    cursor.execute(sql, member_id)
                    member = cursor.fetchone()
                    booking['key'] = member
                    print(member)
                                    

               import json
               jsonStr = json.dumps(bookings, indent=1, sort_keys=True, default=str)
               # then covert json string to json object
               return json.loads(jsonStr)
          

```
Below class will be used by Laboratories to Add Nurses details, we provide the lab_id to make sure that each nurse is added under a Lab
```
class AddNurse(Resource):
     @jwt_required(refresh=True) # Refresh Token
     def post(self):
          json = request.json
          lab_id = json['lab_id']
          surname = json['surname']
          others  =  json['others']
          gender = json['gender']
          email = json['email']
          phone = json['phone']
          password = gen_random(5)

          connection = pymysql.connect(host='localhost',
                                                user='root',
                                                password='',
                                                database='medilab')
          cursor = connection.cursor()

          sql = '''insert into nurses(lab_id, surname, others,
           gender, email, phone, password) 
           values(%s,%s,%s,%s,%s,%s,%s)'''
          
          # data 
          data = (lab_id, surname, others,
           gender, email, encrypt(phone),  hash_password(password))
          
          try:
            cursor.execute(sql, data)
            connection.commit()
            
            send_sms(phone, '''Thank you for Joining MediLab. 
                    Login to Nurse App. Your OTP: {}. Username: {}.'''
                     .format(password, surname))

            return jsonify({'message': 'Nurse Added, Check your Phone for Details'})
          except:
               connection.rollback()
               return jsonify({'message': 'Nurse Add Failed'})

```
Then add another class to View Nurses, we provide the Lab_ID
```
class ViewNurses(Resource):
     @jwt_required(refresh=True) # Refresh Token
     def post(self):
          json = request.json
          lab_id = json['lab_id']
          sql = "select * from nurses where lab_id = %s"
          connection = pymysql.connect(host='localhost',
                                                user='root',
                                                password='',
                                                database='medilab')
          
          cursor = connection.cursor(pymysql.cursors.DictCursor)
          cursor.execute(sql, lab_id)
          count = cursor.rowcount
          if count == 0:
               return jsonify({'message': 'No Nurses Found'})
          else:
               nurses = cursor.fetchall()
               return jsonify(nurses)

```
Next, add this class which allow use allocate a nurse to a given booking invoice no.
```
class TaskAllocation(Resource):
    @jwt_required(refresh=True)  # Refresh Token
    def post(self):
        json = request.json
        nurse_id = json['nurse_id']
        invoice_no = json['invoice_no']

        connection = pymysql.connect(host='localhost',
                                     user='root',
                                     password='',
                                     database='medilab')
        cursor = connection.cursor()

        sql = '''insert into nurse_lab_allocations(nurse_id, invoice_no) 
           values(%s,%s)'''

        # data
        data = (nurse_id, invoice_no)

        try:
            cursor.execute(sql, data)
            connection.commit()
            return jsonify({'message': 'Allocated Suucessfully'})
        except:
            connection.rollback()
            return jsonify({'message': 'Task Not Allocated'})

```

Finally, we configure all above classes created in Part 6, Go to app.py and add below code.
```
# ....
# APIs for Dasboard
from views.views_dashboard import LabSignup, LabSignin, LabProfile, AddLabTests
from views.views_dashboard import ViewLabTests, ViewLabBookings, AddNurse,ViewNurses, TaskAllocation
api.add_resource(LabSignup, '/api/lab_signup')
api.add_resource(LabSignin, '/api/lab_signin')
api.add_resource(LabProfile, '/api/lab_profile')
api.add_resource(AddLabTests, '/api/add_tests')
api.add_resource(ViewLabTests, '/api/view_lab_tests')
api.add_resource(ViewLabBookings, '/api/view_bookings')
api.add_resource(AddNurse, '/api/add_nurse')
api.add_resource(ViewNurses, '/api/view_nurses')
api.add_resource(TaskAllocation, '/api/task_allocation')
# ....
```
Run app.py and test in postman, Wen testing on POST pleae provide the right method 0 POST or GET, the right URL for endpoint and the Payload Body where required. i.e below we test Task Allocation.

Looking at task allocation class created earlie in Part 6, we have a POST function defined,
The URL configured will be http://127.0.0.1:5000/api/task_allocation and we need to provide the nurse_id(identifies the Nurse),the invoice_no(identifies the set of lab tests requested), the invoince No must exist in booking table and nurse id must exist in nurses table

 and the payload looks as below.

```
{
    "nurse_id": 1,
    "invoice_no": "5454545"
}
```
See in Postman below
![image](https://github.com/modcomlearning/MediLab/assets/66998462/422aebbd-dd92-4912-906e-c9e53d629977)



# Part 7
In this section we create APis that will be used by Nurse application, The Nurses are required to Login with credetials given having been given an accout by admin.

Once a Nurse Logs in the application will display their Allocated tasks given that the Nurse ID was used in the admin TaskAllocation.

In views Folder create a file named views_nurse.py and we create a Login and a ViewAssignment Classes.
# TODO






