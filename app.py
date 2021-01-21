#import necessary requirements

from flask import Flask,request,jsonify,make_response
from flask_jwt_extended import JWTManager,jwt_required,create_access_token
from flask_restx import Api, Resource,marshal, fields
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash,check_password_hash
import os
from datetime import datetime

BASE_DIR=os.path.dirname(os.path.realpath(__file__))


app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"]='sqlite:///'+os.path.join(BASE_DIR,'api.db')
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config["SECRET_KEY"]='W@!##@SWE@$@$#@R#@R#R#$#RRSDWE#RWRARR@R@#'

db=SQLAlchemy(app)
api=Api(app)
jwt=JWTManager(app)


#database model
class User(db.Model):
    id=db.Column(db.Integer(),primary_key=True)
    username=db.Column(db.String(25),nullable=False)
    email=db.Column(db.String(80),nullable=False)
    password=db.Column(db.Text())
    date_joined=db.Column(db.DateTime(),default=datetime.utcnow)
    
    def __repr__(self):
        return f"User {self.username}"

    def save(self):
        db.session.add(self)
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def set_password(self,password):
        self.password=generate_password_hash(password)

    def check_password(self,password):
        return check_password_hash(self.password,password)


    def update_username(self,new_name):
        self.username=new_name
        db.session.commit()


    @classmethod
    def get_by_id(cls,id):
        return cls.query.get_or_404(id)

    @classmethod
    def get_by_username(cls,username):
        return cls.query.filter_by(username=username).first()




#model for response marshalling
model=api.model('User',
                {"username":fields.String(),
                 "email":fields.String(),
                 "password":fields.String(),
                 "date_joined":fields.DateTime(dt_format='rfc822')
                 })

@api.route('/auth/signup')
class Authentication(Resource):
    #create a new user
    '''Creates a new user'''
    @api.marshal_with(model,envelope='user')
    @api.expect(model)
    def post(self):
        data=request.get_json()

        new_user=User(username=data.get('username'),
                      email=data.get('email'))

        new_user.set_password(data.get('password'))
        new_user.save()

        return new_user

@api.route('/auth/login')
class Login(Resource):
    ''' Logins a user using a token '''
    def post(self):
        data=request.get_json()

        user= User.get_by_username(data.get('username'))
        if user  and user.check_password(data.get('password')):
            access_token=create_access_token(identity=data.get('username'))
            return make_response(jsonify({"access_token":access_token}),200)



@api.route('/user/<int:id>')
class UserResource(Resource):
    @api.doc(params={"id":"ID for a specific user"})
    @api.marshal_with(model,envelope='user')
    @api.expect(model)
    def put(self,id):
        user=User.get_by_id(id)

        data=request.get_json()

        self.username=data.get('username')

        db.session.commit()

        return user

    @api.doc(params={"id":"ID for a specific user"})
    @api.marshal_with(model,envelope='user')
    def delete(self,id):
        user=User.get_by_id(id)
        user.delete()

        return user

    @api.doc(params={"id":"ID for a specific user"})
    @api.marshal_with(model,envelope="user")
    def get(self,id):
        user=User.get_by_id(id)

        return user

@app.shell_context_processor
def make_shell_context():
    return {
        "app":app,
        "db":db,
        "User":User,
        "api":api
    }

if __name__ == '__main__':
    app.run()
