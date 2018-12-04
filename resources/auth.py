from flask_restful import Resource, reqparse
from flask_jwt_extended import (
    jwt_required,
    get_jwt_identity,
    jwt_refresh_token_required,
    create_access_token,
    create_refresh_token
)
import datetime
import json
from werkzeug.security import safe_str_cmp, check_password_hash

from config import config
from helpers.mysql import Mysql
from helpers.blacklist import (
    add_token_to_database,
    get_user_tokens,
    revoke_token,
    unrevoke_token,
    delete_tokens
)


class AuthLogin(Resource):
    def post(self):
        # Validate and get input vars
        _user_parser = reqparse.RequestParser()
        _user_parser.add_argument('email', type=str, required=True)
        _user_parser.add_argument('password', type=str, required=False)
        _user_parser.add_argument('facebook_id', type=str, required=False)
        data = _user_parser.parse_args()

        if data['facebook_id'] is None and data['password'] is None:
            return {
                'message': 'Invalid input data.',
                'error_code': 'invalid_request'
            }, 400

        # Check user
        db = Mysql()
        user = db.execute_select("SELECT `id`, `facebook_id`, `password` FROM `user` WHERE `email` = %s LIMIT 1", (data['email'],))

        if data['facebook_id'] is not None:
            if len(user) == 1 and user[0]['facebook_id'] == data['facebook_id']:
                pass
            else:
                return {
                    'message': 'Invalid email or password.',
                    'error_code': 'invalid_credentials'
                }, 401
        else:
            if len(user) == 1 and check_password_hash(user[0]['password'], data['password']):
                pass
            else:
                return {
                    'message': 'Invalid email or password.',
                    'error_code': 'invalid_credentials'
                }, 401

        # Create the JWT tokens
        expires_delta = datetime.timedelta(days=config['auth']['access_token']['expires_delta'])
        access_token = create_access_token(identity=user[0]['id'], expires_delta=expires_delta)
        refresh_token = create_refresh_token(identity=user[0]['id'], expires_delta=expires_delta)

        # Store the tokens in our store with a status of not currently revoked.
        add_token_to_database(access_token, 'identity') # app.config['JWT_IDENTITY_CLAIM']
        add_token_to_database(refresh_token, 'identity') # app.config['JWT_IDENTITY_CLAIM']

        return {
            'access_token': access_token,
            'refresh_token': refresh_token
        }, 201


class AuthRefresh(Resource):
    # A revoked refresh tokens will not be able to access this endpoint
    @jwt_refresh_token_required
    def post(self):
        user_identity = get_jwt_identity()
        expires_delta = datetime.timedelta(days=config['auth']['access_token']['expires_delta'])
        access_token = create_access_token(identity=user_identity, expires_delta=expires_delta)
        add_token_to_database(access_token, 'identity') # app.config['JWT_IDENTITY_CLAIM']
        return {'access_token': access_token}, 201


class AuthTokens(Resource):
    # Provide a way for a user to look at their tokens
    @jwt_required
    def get(self):
        user_identity = get_jwt_identity()
        user_sessions = get_user_tokens(user_identity)
        user_sessions = json.dumps(user_sessions, indent=4, sort_keys=True, default=str)
        user_sessions = json.loads(user_sessions)
        return user_sessions, 200

    @jwt_required
    def delete(self):
        # Get input data and check its validity
        _user_parser = reqparse.RequestParser()
        _user_parser.add_argument("tokens", type=str, required=True, location="json")
        data = _user_parser.parse_args()

        if len(data['tokens']) == 0:
            return {
                'message': 'Invalid input data.',
                'error_code': 'invalid_request'
            }, 400

        user_identity = get_jwt_identity()
        delete_tokens(data['tokens'], user_identity)
        return [], 200


class AuthToken(Resource):
    # Get token status
    @jwt_required
    def get(self, token_id):
        return [], 200

    # Provide a way for a user to revoke/unrevoke their tokens
    @jwt_required
    def put(self, token_id):
        # Get input data and check its validity
        _user_parser = reqparse.RequestParser()
        _user_parser.add_argument("action", type=str, required=True, location="json")
        data = _user_parser.parse_args()

        if data['action'] not in ['revoke','unrevoke']:
            return {
                'message': 'Incorrect action.',
                'error_code': 'incorrect_action'
            }, 400

        # Revoke or unrevoke the token based on what was passed to this function
        user_identity = get_jwt_identity()

        if data['action'] == 'revoke':
            if revoke_token(token_id, user_identity) == False:
                return {
                    'message': 'The specified token was not found',
                    'error_code': 'token_not_found'
                }, 404
        else:
            if unrevoke_token(token_id, user_identity) == False:
                return {
                    'message': 'The specified token was not found',
                    'error_code': 'token_not_found'
                }, 404

        return [], 200
