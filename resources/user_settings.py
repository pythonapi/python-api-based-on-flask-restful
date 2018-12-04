from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    get_jwt_identity,
    jwt_required
)

from helpers.mysql import Mysql
from config import config


class UserSettings(Resource):
    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        db = Mysql()
        user_settings = db.execute_select("SELECT * FROM `user_settings` WHERE `user_id` = %s", (user_identity,))
        return user_settings[0]

    @jwt_required
    def put(self):
        # Validate and get input vars
        _user_parser = reqparse.RequestParser()
        _user_parser.add_argument('email_notifications', type=int, required=False)
        _user_parser.add_argument('email_monthly_newsletter', type=int, required=False)
        _user_parser.add_argument('password', type=str, required=False)
        _user_parser.add_argument('password_confirm', type=str, required=False)
        data = _user_parser.parse_args()

        if (data['email_notifications'] is not None and data['email_notifications'] not in [0,1]) or (data['email_monthly_newsletter'] is not None and data['email_monthly_newsletter'] not in [0,1]):
            return {
                'message': 'Invalid input data.',
                'error_code': 'invalid_request'
            }, 400

        if data['password'] is not None and data['password_confirm'] is not None:
            if data['password'] != data['password_confirm'] or len(data['password']) < 8 or len(data['password']) > 255:
                return {
                    'message': 'Invalid input data.',
                    'error_code': 'invalid_request'
                }, 400

        user_identity = get_jwt_identity()

        # Update users password
        db = Mysql()
        if data['password'] is not None and data['password_confirm'] is not None:
            db.execute("UPDATE `user` SET `password` = %s WHERE `id` = %s", (generate_password_hash(data['password']), user_identity))

        # Prepare the data for the user settings
        fields = []
        values = ()
        if data['email_notifications'] is not None:
            fields.append('`email_notifications` = %s')
            values = (*values, data['email_notifications'])

        if data['email_monthly_newsletter'] is not None:
            fields.append('`email_monthly_newsletter` = %s')
            values = (*values, data['email_monthly_newsletter'])

        if len(fields) == 0:
            if data['password'] is not None and data['password_confirm'] is not None:
                return [], 200
            else:
                return {
                    'message': 'Invalid input data.',
                    'error_code': 'invalid_request'
                }, 400

        # Update user settings
        values = (*values, user_identity)
        db.execute("UPDATE `user_settings` SET "+', '.join(fields)+" WHERE `user_id` = %s", values)

        return [], 200
