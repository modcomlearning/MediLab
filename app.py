from datetime import timedelta

from flask import Flask
from flask_restful import Api

app = Flask(__name__)

from datetime import timedelta
from flask_jwt_extended import JWTManager
# # Set up JWT
app.secret_key = "hfjdfhgjkdfhgjkdf865785"
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)
jwt = JWTManager(app)

# Make the App an API
api = Api(app)

# Configure the Views/Endpoints
from views.views import MemberSignUp,MemberSignin, MemberProfile, AddDependant, ViewDependants, Laboratories,\
    LabTests, MakeBooking, MyBookings, MakePayment
api.add_resource(MemberSignUp, '/api/member_signup')
api.add_resource(MemberSignin, '/api/member_signin')
api.add_resource(MemberProfile, '/api/member_profile')
api.add_resource(AddDependant, '/api/add_dependant')
api.add_resource(ViewDependants, '/api/view_dependants')
api.add_resource(Laboratories, '/api/laboratories')
api.add_resource(LabTests, '/api/lab_tests')
api.add_resource(MakeBooking, '/api/make_booking')
api.add_resource(MyBookings, '/api/mybookings')
api.add_resource(MakePayment, '/api/make_payment')
if __name__ == '__main__':
    app.run(debug=True)

# Base URl  127.0.0.1:5000