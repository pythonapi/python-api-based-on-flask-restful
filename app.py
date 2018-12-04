from flask import Flask, jsonify
from flask_restful import Api
from flask_jwt_extended import JWTManager
from pymemcache.client import base
import json
import os

from config import config



##############################
#####     Create app     #####
##############################
def create_app():
    app = Flask(__name__)
    app.config['PROPAGATE_EXCEPTIONS'] = True
    app.config['JWT_BLACKLIST_ENABLED'] = True  # enable blacklist feature
    app.config['JWT_BLACKLIST_TOKEN_CHECKS'] = ['access', 'refresh']  # allow blacklisting for access and refresh tokens
    app.secret_key = config['app']['secret_key']
    api = Api(app)
    jwt = JWTManager(app)

    register_jwt(jwt)
    register_endpoints(api, jwt)

    return app


###############################
#####     JWT Configs     #####
###############################
def register_jwt(jwt):
    from helpers.blacklist import (
        is_token_revoked
    )


    ######################
    ### Set up actions ###
    ######################
    """
    `claims` are data we choose to attach to each jwt payload
    and for each jwt protected endpoint, we can retrieve these claims via `get_jwt_claims()`
    one possible use case for claims are access level control, which is shown below.
    """
    @jwt.user_claims_loader
    def add_claims_to_jwt(identity):  # Remember identity is what we define when creating the access token
        pass


    # This method will check if a token is blacklisted, and will be called automatically when blacklist is enabled
    @jwt.token_in_blacklist_loader
    def check_if_token_in_blacklist(decrypted_token):
        return is_token_revoked(decrypted_token)


    #################################
    ### Set up new error messages ###
    #################################

    # The following callbacks are used for customizing jwt response/error messages.
    # The original ones may not be in a very pretty format (opinionated)
    @jwt.expired_token_loader
    def expired_token_callback():
        return jsonify({
            'message': 'The token has expired.',
            'error_code': 'token_expired'
        }), 401


    @jwt.invalid_token_loader
    def invalid_token_callback(error):  # we have to keep the argument here, since it's passed in by the caller internally
        return jsonify({
            'message': 'Signature verification failed.',
            'error_code': 'invalid_token'
        }), 401


    @jwt.unauthorized_loader
    def missing_token_callback(error):
        return jsonify({
            "description": "Request does not contain an access token.",
            'error_code': 'authorization_required'
        }), 401


    @jwt.needs_fresh_token_loader
    def token_not_fresh_callback():
        return jsonify({
            "description": "The token is not fresh.",
            'error_code': 'fresh_token_required'
        }), 401


    @jwt.revoked_token_loader
    def revoked_token_callback():
        return jsonify({
            "description": "The token has been revoked.",
            'error_code': 'token_revoked'
        }), 401

###########################
#####     Routing     #####
###########################
def register_endpoints(api, jwt):
    from resources.base import Base
    from resources.auth import AuthLogin, AuthRefresh, AuthTokens, AuthToken
    from resources.user import User, UserRegister, UserActivateRequest, UserActivate, UserPasswordResetRequest, UserPasswordReset, UserProfileImage
    from resources.user_settings import UserSettings

    # Base
    api.add_resource(Base, '/')

    # Auth
    api.add_resource(AuthLogin, '/auth/login')
    api.add_resource(AuthRefresh, '/auth/refresh')
    api.add_resource(AuthTokens, '/auth/tokens')
    api.add_resource(AuthToken, '/auth/token/<string:token_id>')

    # User
    api.add_resource(User, '/user')
    api.add_resource(UserRegister, '/user/register')
    api.add_resource(UserActivateRequest, '/user/activate/<string:email>')
    api.add_resource(UserActivate, '/user/activate/<string:activation_key>')
    api.add_resource(UserPasswordResetRequest, '/user/password/reset/<string:email>')
    api.add_resource(UserPasswordReset, '/user/password/reset/<string:password_reset_key>')
    api.add_resource(UserProfileImage, '/user/profile/image')

    # User Settings
    api.add_resource(UserSettings, '/user/settings')



#########################
#####     Start     #####
#########################
app = create_app()

if __name__ == '__main__':
    app.run(port=config['app']['port'], debug=config['app']['debug'])
