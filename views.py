import pymysql
import pymysql.cursors
from flask_restful import Resource
from flask import *
from functions import *


class SignUp(Resource):
    def post(self):
        data = request.json
        username = data['surname']
        others = data['others']
        gender = data['gender']
        email = data['email']
        phone = data['phone']
        dob = data['dob']
        password = data['password']
        location_id = data['location_id']
        response = passwordValidity(password)
        if response == True:
            connection = pymysql.connect(host='localhost', user='root', password='',
                                         database='MediLab')
            cursor = connection.cursor()
            sql = "insert into members (surname, others, gender, email, phone, dob, password, location_id) values(%s, %s, %s, %s, %s, %s, %s, %s)"
            try:
                cursor.execute(sql, (username, others, gender, email, phone, dob, hash_password(password), location_id))
                connection.commit()
                send_sms(phone, "Registration Successful.")

                return jsonify({'message': 'POST SUCCESS. RECORD SAVED'})
            except:
                connection.rollback()
                return jsonify({'message': 'POST FAILED. RECORD NOT SAVED'})
        else:
            return jsonify({'message': response})

class SignIn(Resource):
    def post(self):
            data = request.json
            email = data['email']
            password =  data['password']

            # check if email exists
            connection = pymysql.connect(host='localhost', user='root', password='',
                                     database='MediLab')

            sql = "select * from members where email = %s"
            cursor = connection.cursor(pymysql.cursors.DictCursor)
            cursor.execute(sql, (email))
            if cursor.rowcount == 0:
                return jsonify({'message': 'Email does not Exist!'})
            else:
                row = cursor.fetchone()
                hashed_password = row['password']
                # verify
                status = hash_verify(password, hashed_password)
                if status == True:
                    return jsonify({'message': 'Logged Successful'})

                elif status == False:
                    return jsonify({'message': 'Logged Not Successful'})
                else:
                    return jsonify({'message': 'Something went wrong'})


