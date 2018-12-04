from helpers.mysql import Mysql
import string
import random


def generate_activation_key():
    '''
    Generates an unique activation key.
    '''
    activation_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
    db = Mysql()
    user = db.execute_select("SELECT u.`id` FROM `user` AS u WHERE u.`activation_key` = %s", (activation_key,))
    if len(user) > 0:
        activation_key = generate_activation_key()
    return activation_key

def generate_forgotten_password_key():
    '''
    Generates an unique forgotten password key.
    '''
    forgotten_password_key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(20))
    db = Mysql()
    user = db.execute_select("SELECT u.`id` FROM `user` AS u WHERE u.`forgotten_password_key` = %s", (forgotten_password_key,))
    if len(user) > 0:
        forgotten_password_key = generate_forgotten_password_key()
    return forgotten_password_key
