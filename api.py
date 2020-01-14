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
from six import string_types
import scoring

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

    def __init__(self, required=False, nullable=False):
        self.required = required
        self.nullable = nullable
        self.label = None

    def __get__(self, instance, owner):
        if instance is None:
            return self
        return instance.__dict__.get(self.label)


class CharField(Field):
    def validate(self, value):
        if not isinstance(value, string_types):
            raise ValueError("This field must be a string")


class ArgumentsField(Field):
    def validate(self, value):
        if not isinstance(value, dict):
            raise ValueError("This field must be a dict")


class EmailField(CharField):
    def validate(self, value):
        if "@" not in value:
            raise ValueError("Invalid email address")


class PhoneField(Field):
    def validate(self, value):
        if not isinstance(value, string_types) and not isinstance(value, int):
            raise ValueError("Phone number must be number or string")
        if not len(str(value)) == 11 or not str(value).startswith("7")  or not str(value).isdigit():
            raise ValueError("Phone number should be 7**********")


class DateField(Field):
    def validate(self, value):
        try:
            datetime.datetime.strptime(value, '%d.%m.%Y')
        except ValueError:
            raise ValueError("Incorect date format, should be DD.MM.YYYY")


class BirthDayField(DateField):
    def validate(self, value):
        super(BirthDayField, self).validate(value)
        bdate = datetime.datetime.strptime(value, '%d.%m.%Y')
        if datetime.datetime.now().year - bdate.year > 70:
            raise ValueError("Incorrect birth day")


class GenderField(Field):
    def validate(self, value):
        if value not in GENDERS:
            raise ValueError("Gender must be equal to 0, 1 or 2")


class ClientIDsField(Field):
    def validate(self, values):
        if not isinstance(values, list) or not all(isinstance(v, int) and v >= 0 for v in values):
            raise ValueError("Client IDs should be list or positive integers")


class FieldsMetaclass(type):
    def __new__(meta, name, bases, attrs):
        fields = {}
        for field_name, field in attrs.items():
            if isinstance(field, Field):
                fields[field_name] = field
        attrs['fields'] = fields
        return super(FieldsMetaclass, meta).__new__(meta, name, bases, attrs)



class BaseRequest(object):
    __metaclass__ = FieldsMetaclass

    def __init__(self, **kwargs):
        self.base_fields = []
        for field_name, value in kwargs.items():
            if field_name in self.fields.keys():
                setattr(self, field_name, value)
                self.base_fields.append(field_name)


    def validate(self):
        cls = self.__class__
        for field in cls.fields:
            d = getattr(cls, field)
            if field not in self.__dict__:
                if d.required:
                    raise ValueError(
                        "Required field %s is not defined!" % field)
                continue
            value = self.__dict__[field]
            if not d.nullable and value in [None, (), [], '']:
                raise ValueError("Non-nullable field %s is %r" %
                                 (field, value))
            if hasattr(d, 'validate') and callable(d.validate):
                try:
                    d.validate(value)
                except (TypeError, ValueError) as exc:
                    raise ValueError("Field %s (type %s) invalid: %s (%r)" %
                                     (
                                         field,
                                         d.__class__.__name__,
                                         exc.message,
                                         value
                                     )
                                     )


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
        if not (("phone" in self.base_fields and "email" in self.base_fields) or
                ("first_name" in self.base_fields and "last_name" in self.base_fields) or
                ("gender" in self.base_fields and "birthday" in self.base_fields)):
            raise ValueError("At least one of the pairs should be defined: "
                         "first/last name, email/phone, birthday/gender")


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


def method_handler(request, ctx, store):
    handlers = {"online_score": OnlineScoreRequest,
                "clients_interests": ClientsInterestsRequest}

    method_request = MethodRequest(**request['body'])

    try:
        method_request.validate()
    except ValueError, e:
        return e.message, INVALID_REQUEST

    if not check_auth(method_request):
        return ERRORS[FORBIDDEN], FORBIDDEN

    if method_request.method not in handlers:
        err = "Unknown method %s, choose any of: %s" % (handlers.method,
                                                        request_map.keys())
        return err, INVALID_REQUEST

    if method_request.method in handlers:
        req = handlers[method_request.method](**method_request.arguments)
        try:
            req.validate()
        except ValueError, e:
            return e.message, INVALID_REQUEST

    if method_request.method == "online_score":
        score_req = OnlineScoreRequest(**method_request.arguments)

        ctx['has'] = [f for f in score_req.base_fields if getattr(score_req, f) is not None]

        if method_request.is_admin:
            return {"score": 42}, OK
        result = {"score": scoring.get_score(store, score_req.phone, score_req.email,
                 score_req.birthday, score_req.gender, score_req.first_name, score_req.last_name)}

    if method_request.method == "clients_interests":
        interests_req = ClientsInterestsRequest(**method_request.arguments)

        ctx['nclients'] = len(interests_req.client_ids)
        result = {clid: scoring.get_interests(store, clid)
                for clid in interests_req.client_ids}

    return result, OK



class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}

        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
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
