# Import Required modules
import pymysql
from flask_restful import *
from flask import *
from functions import *
import pymysql.cursors

# import JWT Packages
from flask_jwt_extended import create_access_token, jwt_required, set_access_cookies
from flask_jwt_extended import get_jwt


# # Refreshing Tokens
# @app.after_request
# def refresh_expiring_jwts(response):
#     try:
#         exp_timestamp = get_jwt()["exp"]
#         now = datetime.now()
#         target_timestamp = datetime.timestamp(now + timedelta(minutes=30))
#         if target_timestamp > exp_timestamp:
#             access_token = create_access_token(identity='admin')
#             set_access_cookies(response, access_token)
#         return response
#     except (RuntimeError, KeyError):
#         # Case where there is not a valid JWT. Just return the original response
#         return response


# Member SignUp.
class MemberSignUp(Resource):
    def post(self):
        # Connect to MySQL
        json = request.json
        surname = json['surname']
        others = json['others']
        gender = json['gender']
        email = json['email']
        phone = json['phone']
        dob = json['dob']
        password = json['password']
        location_id = json['location_id']

        # Validate Password
        response = passwordValidity(password)
        if response == True:
            if check_phone(phone):
                connection = pymysql.connect(host='localhost',
                                             user='root',
                                             password='',
                                             database='medilab')
                cursor = connection.cursor()
                # Insert Data
                sql = ''' Insert into members(surname, others,  gender, email,
                   phone, dob, password, location_id)values(%s, %s, %s, %s,%s, 
                   %s, %s, %s) '''
                # Provide Data

                data = (surname, others, gender, encrypt(email), encrypt(phone),
                        dob, hash_password(password), location_id)
                try:
                    cursor.execute(sql, data)
                    connection.commit()
                    # Send SMS/EMail
                    code = gen_random(4)
                    send_sms(phone, '''Thank you for Joining MediLab. 
                        Your Secret No: {}. Do not share.'''.format(code))
                    return jsonify({'message': 'Successful Registered'})
                except:
                    connection.rollback()
                    return jsonify({'message': 'Failed. Try Again'})

            else:
                return jsonify({'message': 'Invalid Phone +254'})

        else:
            return jsonify({'message': response})


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
                                     database='medilab')

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
                return jsonify({'message': member})

            else:
                return jsonify({'message': 'Login Failed'})


# can we use Encrypted Email?
# Read on JWT Tokens? What are they? WHere are they Used?
# Tommorow
# Token, Member Profile, Add Dependant. View Dependants
# Member  Profile
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


# Add Deoendant.
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
        # [{}, {} ]  - JSON Array - with JSON Onjects






