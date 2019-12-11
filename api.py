#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
#from http.server import HTTPServer, BaseHTTPRequestHandler
from six import string_types
from scoring import get_score, get_interests
#from store import Store
Store = None

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}


class Field(object):
    empty_values = (None, (), [], '')

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable

    def validate(self, value):
        pass

    def get_value(self, value):
        return value


class CharField(Field):
    def validate(self, value):
        if not isinstance(value, string_types):
            raise ValueError("This field must be a string")

    def get_value(self, value):
        return str(value)




class ArgumentsField(Field):
    def validate(self, value):
        if not isinstance(value, dict):
            raise ValueError("This field must be a dict")

    def get_value(self, value):
        return super().get_value(value)

class EmailField(CharField):
    def validate(self, value):
#        super(EmailField, self).validate(value)  # should test it comment
        if "@" not in value:
            raise ValueError("Invalid email address")

    def get_value(self, value):
        return super().get_value(value)


class PhoneField(Field):
    def validate(self, value):
        if not isinstance(value, string_types) and not isinstance(value, int):
            raise ValueError("Phone number must be numeric or string value")
        if not len(str(value)) == 11 or not str(value).startswith("7")  or not str(value).isdigit():
            raise ValueError("Phone number should be 7**********")

    def get_value(self, value):
        return super().get_value(value)

class DateField(Field):
    def validate(self, value):
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError:
            raise ValueError("Incorect date format, should be DD.MM.YYYY")

    def get_value(self, value):
        return datetime.datetime.strptime(value, '%d.%m.%Y')

class BirthDayField(Field):
    def validate(self, value):
        super(BirthDayField, self).validate(value)
        bdate = datetime.datetime.strptime(value, '%d.%m.%Y')
        if datetime.datetime.now().year - bdate.year > 70:
            raise ValueError("Incorrect birth day")

    def get_value(self, value):
        return datetime.datetime.strptime(value, '%d.%m.%Y')


class GenderField(Field):
    def validate(self, value):
        if value not in GENDERS:
            raise ValueError("Gender must be equal to 0, 1 or 2")

    def get_value(self, value):
        return int(value)


class ClientIDsField(Field):
    def validate(self, values):
        if (not isinstance(values, list) or
                not all(isinstance(i, int) for i in values)):
            raise ValueError("Client IDs should be list of ints")

    def get_value(self, value):
        return super().get_value(value)

class FieldOwner(type):
    def __new__(meta, name, bases, attrs):
        new_class = super(FieldOwner, meta).__new__(meta, name, bases, attrs)
        fields = {}
        for field_name, field in attrs.items():
            if isinstance(field, Field):
                fields[field_name] = field
        new_class.fields = fields
#        return super(FieldOwner, meta).__new__(meta, name, bases, attrs)
        return new_class


class BaseRequest(object):
    __metaclass__ = FieldOwner

    def __init__(self, **kwargs):
        self._errors = {}
        self.base_fields = []
        for field_name, value in kwargs.items():
            setattr(self, field_name, value)
            self.base_fields.append(field_name)

    def __getitem__(self, name):
        """Return field's value in appropriate format"""
        if name in self.base_fields:
            value = getattr(self, str(name), None)
            field = self.fields[name]
            return field.get_value(value)
        else:
            return None

    def validate(self):
        for name, field in self.fields.items():
            if name not in self.base_fields:
                if field.required:
                    self._errors[name] = "This field is required"
                continue

            value = getattr(self, name)
            if value in field.empty_values and not field.nullable:
                self._errors[name] = "This field can't be blank"

            try:
                field.validate(value)
            except ValueError as e:
                self._errors[name] = e

    @property
    def errors(self):
        return self._errors

    def is_valid(self):
        return not self.errors


class ClientsInterestsRequest(BaseRequest):
    client_ids = ClientIDsField(required=True)
    date = DateField(required=False, nullable=True)


class OnlineScoreRequest(BaseRequest):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def validate(self):
        super(OnlineScoreRequest, self).validate()
        if not self._errors:
            if not (("phone" in self.base_fields and "email" in self.base_fields) or
                    ("first_name" in self.base_fields and "last_name" in self.base_fields) or
                    ("gender" in self.base_fields and "birthday" in self.base_fields)):
                self._errors["arguments"] = "No valid arguments pair"



class MethodRequest(BaseRequest):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=False)


    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(datetime.datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT).hexdigest()
    else:
        digest = hashlib.sha512(request.account + request.login + SALT).hexdigest()
    if digest == request.token:
        return True
    return False


def online_score_handler(request, ctx, store):
    r = OnlineScoreRequest(**request.arguments)
    r.validate()

    if not r.is_valid():
        return r.errors, INVALID_REQUEST

    ctx['has'] = r.base_fields
    if request.is_admin:
        return {"score": 42}, OK
    else:
        score = get_score(store, r['phone'], r['email'], birthday=r['birthday'], gender=r['gender'],
                          first_name=r['first_name'], last_name=r['last_name'])
        return {"score": score}, OK


def clients_interests_handler(request, ctx, store):
    r = ClientsInterestsRequest(**request.arguments)
    r.validate()
    if not r.is_valid():
        return r.errors, INVALID_REQUEST

    response = {}
    for cid in r.client_ids:
        response[cid] = get_interests(store, cid)
    ctx["nclients"] = len(r.client_ids)

    return response, OK



def method_handler(request, ctx, store):
    handlers = {"online_score": online_score_handler,
                "clients_interests": clients_interests_handler}

    method_request = MethodRequest(**request["body"])
    method_request.validate()

    if not method_request.is_valid():
        return method_request.errors, INVALID_REQUEST

    if not check_auth(method_request):
        return ERRORS[FORBIDDEN], FORBIDDEN

    response, code = handlers[method_request.method](method_request, ctx, store)

    return response, code



class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        print(headers) #User-Agent: curl/7.29.0 Host: 127.0.0.1:8080 Accept: */* Content-Type: application/json Content-Length: 388
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
#        print("context is:", context) # ('context is:', {'request_id': '4e04c1d6748442c0aa996e2357eb7524'})

        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
#            print("request is:", request) #'request is:', {u'arguments': {u'first_name': u'\u0430\u0432', u'last_name': u'\u043e\u0432', u'gender': 1, u'phone': u'79175002040', u'birthday': u'01.01.1990', u'email': u'stupnikov@otus.ru'}, u'account': u'horns&hoofs', u'login': u'h&f', u'token': u'55cc9ce545bcd144300fe9efc28e65d415b923ebb6be1e19d2750a2c03e80dd209a27954dca045e5bb12418e7d89b6d718a9e35af34e14e1d5bcd5a08f21fc95', u'method': u'online_score'}
            path = self.path.strip("/")
#            print(path) # mathod
#            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
#                    response, code = method_handler({"body": request, "headers": self.headers}, context, self.store)
#                    print(response) # None
#                    print(code)     # None
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        print("fefef" + str(r)) # fefef{'code': 200, 'response': 'None'}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
