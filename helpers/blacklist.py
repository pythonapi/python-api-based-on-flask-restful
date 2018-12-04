from flask_jwt_extended import decode_token
import datetime

from helpers.cache import Cache
from helpers.mysql import Mysql


def _epoch_utc_to_datetime(epoch_utc):
    """
    Helper function for converting epoch timestamps (as stored in JWTs) into
    python datetime objects (which are easier to use with sqlalchemy).

    :param epoch_utc:
    """
    return datetime.datetime.fromtimestamp(epoch_utc)


def add_token_to_database(encoded_token, identity_claim):
    """
    Adds a new token to the cache and database. It is not revoked when it is added.

    :param encoded_token:
    :param identity_claim:
    """
    # Prepare
    decoded_token = decode_token(encoded_token)
    jti = decoded_token['jti']
    token_type = decoded_token['type']
    user_identity = decoded_token[identity_claim]
    revoked = False
    expires = _epoch_utc_to_datetime(decoded_token['exp'])

    # Save
    cache = Cache()
    cache.set('token_'+jti, str({
        'jti': jti,
        'token_type': token_type,
        'user_identity': user_identity,
        'revoked': revoked,
        'expires': expires
    }))
    db = Mysql()
    db.execute("INSERT INTO `user_session` (`user_id`,`jti`,`token_type`,`user_identity`,`revoked`,`expires`) VALUES (%s,%s,%s,%s,%s,%s)",
               (user_identity,jti,token_type,user_identity,revoked,expires))


def is_token_revoked(decoded_token):
    """
    Checks if the given token is revoked or not. Because we are adding all the
    tokens that we create into this database, if the token is not present
    in the database we are going to consider it revoked, as we don't know where
    it was created.

    :param decoded_token:
    """
    jti = decoded_token['jti']
    cache = Cache()
    if cache.get('token_'+jti) is None:
        return True
    token = eval(cache.get('token_'+jti).decode("utf-8"))

    if token is not None:
        return token['revoked']
    else:
        db = Mysql()
        token = db.execute_select("SELECT * FROM `user_session` WHERE `jti` = %s", (jti,))

        if len(token) > 0:
            return token[0]['revoked']
        else:
            return True


def get_user_tokens(user_identity):
    """
    Returns all of the tokens, revoked and unrevoked, that are stored for the
    given user

    :param user_identity:
    """
    db = Mysql()
    return db.execute_select("SELECT * FROM `user_session` WHERE `user_identity` = %s", (user_identity,))


def revoke_token(token_id, user_identity):
    """
    Revokes the given token. Raises a TokenNotFound error if the token does not exist in the database.

    :param token_id: Id of the token
    :param user_identity:
    :type token_id: int
    """
    db = Mysql()
    token = db.execute_select("SELECT * FROM `user_session` WHERE `user_identity` = %s AND `id` = %s", (user_identity,token_id))

    if len(token) > 0:
        token = token[0]
        token['revoked'] = 1
        cache = Cache()
        cache.set('token_'+token['jti'], str(token))
        db.execute("UPDATE `user_session` SET `revoked` = %s WHERE `user_identity` = %s AND `id` = %s", (1,user_identity,token_id))
    else:
        return False


def unrevoke_token(token_id, user_identity):
    """
    Unrevokes the given token. Raises a TokenNotFound error if the token does not exist in the database

    :param token_id: Id of the token
    :param user_identity:
    :type token_id: int
    """
    db = Mysql()
    token = db.execute_select("SELECT * FROM `user_session` WHERE `user_identity` = %s AND `id` = %s", (user_identity,token_id))

    if len(token) > 0:
        token = token[0]
        token['revoked'] = 0
        cache = Cache()
        cache.set('token_'+token['jti'], str(token))

        db.execute("UPDATE `user_session` SET `revoked` = %s WHERE `user_identity` = %s AND `id` = %s", (0,user_identity,token_id))
    else:
        return False


def delete_tokens(token_ids_list, user_identity):
    """
    Delete tokens.

    :param tokens: List of tokens
    :type tokens: list
    """
    # Delete from cache
    db = Mysql()
    tokens = db.execute_select("SELECT `jti` FROM `user_session` WHERE `user_id` = %s AND `id` IN (%s)", (user_identity, token_ids_list))
    if len(tokens) > 0:
        for token in tokens:
            cache = Cache()
            cache.delete('token_'+token['jti'])

    # Delete from DB
    db.execute("DELETE FROM `user_session` WHERE `user_id` = %s AND `id` IN (%s)", (user_identity, token_ids_list))


def prune_database():
    """
    Delete tokens that have expired from the database.
    How (and if) you call this is entirely up you. You could expose it to an
    endpoint that only administrators could call, you could run it as a cron,
    set it up with flask cli, etc.
    """
    now = datetime.now()
    db = Mysql()
    expired_tokens = db.execute_select("SELECT * FROM `user_session` WHERE `expires` < NOW()", (now,))

    for expired_token in expired_tokens:
        cache = Cache()
        cache.delete('token_'+expired_token['jti'])

    db.execute("DELETE FROM `user_session` WHERE `expires` < %s", (now,))


class TokenNotFound(Exception):
    """
    Indicates that a token could not be found in the database
    """
    pass
