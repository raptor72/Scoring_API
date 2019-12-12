import hashlib
import datetime


SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"

def check_auth(login):
    if login == ADMIN_LOGIN:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    return digest



print(check_auth('admin'))


