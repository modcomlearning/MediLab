from flask import Flask
from flask_restful import Api
# from flask_jwt_extended import JWTManager
app = Flask(__name__)

# # Set up JWT
# app.secret_key = "hfjdfhgjkdfhgjkdf865785"
# jwt = JWTManager(app)

# Make the App an API
api = Api(app)

# Configure the Views/Endpoints
# ....
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant, ViewDependants
api.add_resource(MemberSignUp, '/api/member_signup')
api.add_resource(MemberSignin, '/api/member_signin')
api.add_resource(MemberProfile, '/api/member_profile')
api.add_resource(AddDependant, '/api/add_dependant')
api.add_resource(ViewDependants, '/api/view_dependants')


if __name__ == '__main__':
    app.run(debug=True)

# Base URl  127.0.0.1:5000