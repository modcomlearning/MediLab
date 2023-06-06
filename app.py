from flask import *
from flask_restful import Api
app = Flask(__name__)

api=Api(app)


from views import SignUp, SignIn
api.add_resource(SignUp, '/api/member_signup')
api.add_resource(SignIn, '/api/member_signin')

if __name__ == '__main__':
    app.run(debug=True)
