from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    create_access_token,
    create_refresh_token,
    jwt_refresh_token_required,
    get_jwt_identity,
    jwt_required,
    get_raw_jwt
)
from helpers.key_generator import (
    generate_activation_key,
    generate_forgotten_password_key
)
import string
import random
from werkzeug.security import generate_password_hash
from werkzeug.datastructures import FileStorage
from dateutil.relativedelta import relativedelta
import datetime
import os

from helpers.mailer import Mailer
from config import config
from helpers.mysql import Mysql


class User(Resource):
    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        db = Mysql()
        user = db.execute_select("SELECT up.*, u.`email` FROM `user_profile` AS up LEFT JOIN `user` AS u ON u.`id` = up.`user_id` WHERE up.`user_id` = %s", (user_identity,))
        if len(user) == 0:
            return {
                'message': 'User not found.',
                'error_code': 'user_not_found'
            }, 400
        return user[0]

    @jwt_required
    def put(self):
        # Validate the input data
        _user_parser = reqparse.RequestParser()
        _user_parser.add_argument('first_name', type=str, required=False, location="json")
        _user_parser.add_argument('last_name', type=str, required=False, location="json")
        _user_parser.add_argument('headline', type=str, required=False, location="json")
        _user_parser.add_argument('country_id', type=str, required=False, location="json")
        _user_parser.add_argument('city_id', type=str, required=False, location="json")
        data = _user_parser.parse_args()

        # Prepare the data
        fields = []
        values = ()
        vars = ['first_name','last_name','headline','country_id','city_id']
        for var in vars:
            if data[var] is not None:
                fields.append('`'+var+'` = %s')
                values = (*values, data[var])

        if len(fields) == 0:
            return {
                'message': 'Invalid input data.',
                'error_code': 'invalid_request'
            }, 400

        # Update user
        user_identity = get_jwt_identity()
        values = (*values, user_identity)
        db = Mysql()
        db.execute("UPDATE `user_profile` SET "+', '.join(fields)+" WHERE `user_id` = %s", values)

        return [], 200


class UserRegister(Resource):
    def post(self):
        # Get and validate input data
        _user_parser = reqparse.RequestParser()
        _user_parser.add_argument('email', type=str, required=True, location="json")
        _user_parser.add_argument('password', type=str, required=False, location="json")
        _user_parser.add_argument('facebook_id', type=str, required=False, location="json")
        data = _user_parser.parse_args()

        if data['facebook_id'] is None and data['password'] is None:
            return {
                'message': 'Invalid input data.',
                'error_code': 'invalid_request'
            }, 400

        # Check if this user already exists
        db = Mysql()
        user = db.execute_select("SELECT * FROM `user` WHERE `email` = %s", (data['email'],))
        if len(user) > 0:
            if user[0]['facebook_id'] == "" and data['facebook_id'] is not None:
                db.execute("UPDATE `user` SET `facebook_id` = %s WHERE `email` = %s", (data['facebook_id'],data['email']))

            return {
                'message': 'A user with that email already exists',
                'error_code': 'user_exists'
            }, 400

        # Create user
        if data['facebook_id'] is not None:
            # facebook_id
            db.execute("INSERT INTO `user` (`email`, `facebook_id`, `is_active`) VALUES(%s, %s, %s)", (data['email'], data['facebook_id'], 1))
        else:
            activation_key = generate_activation_key()
            db.execute("INSERT INTO `user` (`email`, `password`, `activation_key`) VALUES(%s, %s, %s)", (data['email'], generate_password_hash(data['password']), activation_key))

        # Send activation mail
        mailer = Mailer()
        mailer.send(
            'user_register_and_activation',
            data['email'],
            USER_ACTIVATION_URL=config['general']['public_domain']+'/u/activation/key'+activation_key,
            USER_EMAIL=data['email']
        )

        return [], 201


class UserActivateRequest(Resource):
    # Return the activation_key by email address
    def get(self, email: str):
        # Check if this user already exists
        db = Mysql()
        user = db.execute_select("SELECT u.`activation_key`, up.`first_name` FROM `user` AS u LEFT JOIN `user_profile` AS up ON up.`user_id` = u.`id` WHERE u.`email` = %s", (email,))

        if len(user) == 0:
            return {
                'message': 'A user with that email does not exist',
                'error_code': 'user_does_not_exist'
            }, 400

        # Send activation request mail
        mailer = Mailer()
        mailer.send(
            'user_request_activation',
            email,
            USERS_FIRST_NAME=user[0]['first_name'],
            USER_EMAIL=email,
            USER_ACTIVATION_URL=config['general']['public_domain']+'/u/activation/key'+user[0]['activation_key']
        )

        return {
            'activation_key': user[0]['activation_key']
        }, 200


class UserActivate(Resource):
    # Activates the user by activation_key
    def put(self, activation_key: str):
        # Check if this user already exists
        db = Mysql()
        user = db.execute_select("SELECT * FROM `user` WHERE `activation_key` = %s", (activation_key,))

        if len(user) == 0:
            return {
                'message': 'The activation key is invalid.',
                'error_code': 'invalid_activation_key'
            }, 400

        db.execute("UPDATE `user` SET `activation_key` = %s, `is_active` = %s WHERE `activation_key` = %s", ('',1,activation_key))
        return [], 200


class UserPasswordResetRequest(Resource):
    forgotten_password_key_expiration_period = 4 # weeks

    # Create a request for password reset
    def post(self, email: str):
        # Check if this user exists
        db = Mysql()
        user = db.execute_select("SELECT u.`id`, up.`first_name` FROM `user` AS u LEFT JOIN `user_profile` AS up ON up.`user_id` = u.`id` WHERE u.`email` = %s", (email,))

        if len(user) == 0:
            return {
                'message': 'A user with that email does not exist',
                'error_code': 'user_does_not_exist'
            }, 400

        # Set forgotten password key and return it
        forgotten_password_key = generate_activation_key()
        forgotten_password_key_expires_on = (datetime.datetime.now() + relativedelta(weeks=self.forgotten_password_key_expiration_period)).strftime('%Y-%m-%d 00:00:00')
        db.execute("UPDATE `user` SET `forgotten_password_key` = %s, `forgotten_password_key_expires_on` = %s WHERE `email` = %s", (forgotten_password_key,forgotten_password_key_expires_on,email))

        # Send activation request mail
        mailer = Mailer()
        mailer.send(
            'user_password_reset',
            email,
            USERS_FIRST_NAME=user[0]['first_name'],
            USER_FORGOTTEN_PASSWORD_URL=config['general']['public_domain']+'/u/forgotten/password/key'+forgotten_password_key
        )

        return {
            'password_reset_key': forgotten_password_key
        }, 200


class UserPasswordReset(Resource):
    # Reset the password
    def put(self, password_reset_key: str):
        # Check if this user already exists
        db = Mysql()
        user = db.execute_select("SELECT * FROM `user` WHERE `forgotten_password_key` = %s AND `forgotten_password_key_expires_on` > NOW()", (password_reset_key,))

        if len(user) == 0:
            return {
                'message': 'The password reset key is invalid or expired.',
                'error_code': 'invalid_password_reset_key'
            }, 400

        # Get password and password confirm and check their validity
        _user_parser = reqparse.RequestParser()
        _user_parser.add_argument("password", type=str, required=True, location="json")
        _user_parser.add_argument("password_confirm", type=str, required=True, location="json")
        data = _user_parser.parse_args()

        if data['password'] != data['password_confirm'] or len(data['password']) < 8 or len(data['password']) > 255:
            return {
                'message': 'Invalid input data.',
                'error_code': 'invalid_request'
            }, 400

        # Update users password
        db.execute("UPDATE `user` SET `password` = %s, `forgotten_password_key` = %s, `forgotten_password_key_expires_on` = %s WHERE `forgotten_password_key` = %s", (generate_password_hash(data['password']), '', '', password_reset_key))
        return [], 200


class UserProfileImage(Resource):
    file_extensions = ('.png','.jpg','.jpeg')

    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        db = Mysql()
        user = db.execute_select("SELECT `profile_image_url` FROM `user_profile` WHERE `user_id` = %s", (user_identity,))

        if user[0]['profile_image_url'] != '':
            return {
                'profile_image_url': user[0]['profile_image_url']
            }
        return {
            'profile_image_url': config['general']['file_storage']+'default.jpg'
        }

    @jwt_required
    def delete(self):
        user_identity = get_jwt_identity()
        db = Mysql()
        user = db.execute_select("SELECT `profile_image_url` FROM `user_profile` WHERE `user_id` = %s", (user_identity,))

        if user[0]['profile_image_url'] != '':
            basedir = os.path.abspath(os.path.dirname(__file__))
            delete_path = basedir + user[0]['profile_image_url']
            os.remove(delete_path)
            db.execute("UPDATE `user_profile` SET `profile_image_url` = %s WHERE `user_id` = %s", ('', user_identity,))

        return [], 200

    @jwt_required
    def post(self):
        # Get input data
        _user_parser = reqparse.RequestParser()
        _user_parser.add_argument('file', type=FileStorage, required=True, location='files')
        data = _user_parser.parse_args()

        # Get file
        file = data['file']
        name, ext = os.path.splitext(file.filename)

        # Check if file covers the requirements
        if ext not in self.file_extensions:
            return {
                'message': 'The file extension is not allowed.',
                'error_code': 'file_extension_not_allowed'
            }, 400

        # Create path where we will save the file
        directory = config['general']['file_storage']+datetime.datetime.now().strftime(("%Y/%m"))
        basedir = os.path.abspath(os.path.dirname(__file__))
        save_path = basedir+directory
        if not os.path.exists(save_path):
            os.makedirs(save_path)

        # Save file
        new_file_name = datetime.datetime.now().strftime(("%Y%m%d"))+''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))+ext
        file_path = "{path}/{file}".format(path=save_path, file=new_file_name)
        file.save(file_path)

        # Update profile image of the user in the database
        file_url = "{directory}/{file}".format(directory=directory, file=new_file_name)
        user_identity = get_jwt_identity()
        db = Mysql()
        db.execute("UPDATE `user_profile` SET `profile_image_url` = %s WHERE `user_id` = %s", (file_url,user_identity,))
        return [], 200
