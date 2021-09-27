#!/usr/bin/env python
"""
A simple app to create a JWT token.
"""
import os
import logging
import datetime
import functools
import jwt

# pylint: disable=import-error
from flask import Flask, jsonify, request, abort


JWT_SECRET = os.environ.get('JWT_SECRET', 'abc123abc1234')
LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')


def _logger():
    '''
    Setup logger format, level, and handler.

    RETURNS: log object
    '''
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')

    log = logging.getLogger(__name__)
    log.setLevel(LOG_LEVEL)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)

    log.addHandler(stream_handler)
    return log


LOG = _logger()
LOG.debug("Starting with log level: %s" % LOG_LEVEL )
APP = Flask(__name__)

def require_jwt(function):
    """
    Decorator to check valid jwt is present.
    """
    @functools.wraps(function)
    def decorated_function(*args, **kws):
        if not 'Authorization' in request.headers:
            abort(401)
        data = request.headers['Authorization']
        LOG.info("data from request.headers type %s" % type(data))
        LOG.info("data from request.headers %s" %data)
        token = str.replace(str(data), 'Bearer ', '')
        try:
            jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        except: # pylint: disable=bare-except
            abort(401)

        return function(*args, **kws)
    return decorated_function


@APP.route('/', methods=['POST', 'GET'])
def health():
    return jsonify("Healthy")


@APP.route('/auth', methods=['POST'])
def auth():
    """
    Create JWT token based on email.
    """
    request_data = request.get_json()
    email = request_data.get('email')
    LOG.info("In post auth email %s" %email)
    password = request_data.get('password')
    LOG.info("In post auth password %s" %password)
    if not email:
        LOG.error("No email provided")
        return jsonify({"message": "Missing parameter: email"}, 400)
    if not password:
        LOG.error("No password provided")
        return jsonify({"message": "Missing parameter: password"}, 400)
    body = {'email': email, 'password': password}
    LOG.info("body type %s" % type(body))
    user_data = body
    LOG.info("user_data type %s" %type(user_data))

    return jsonify(token=_get_jwt(user_data).decode('utf-8'))


@APP.route('/contents', methods=['GET'])
def decode_jwt():
    """
    Check user token and return non-secret data
    """
    if not 'Authorization' in request.headers:
        abort(401)
    data = request.headers['Authorization']
    LOG.info("data type %s" % type(data))
    LOG.info("data  %s" % data)

    token = str.replace(str(data), 'Bearer ', '')
    try:
        data = jwt.decode(token, JWT_SECRET, algorithms=['HS256'])
        LOG.info("data token type %s" % type(data))
    except: # pylint: disable=bare-except
        abort(401)


    response = {'email': data['email'],
                'exp': data['exp'],
                'nbf': data['nbf'] }
    return jsonify(**response)


def _get_jwt(user_data):
    exp_time = datetime.datetime.utcnow() + datetime.timedelta(weeks=2)
    payload = {'exp': exp_time,
               'nbf': datetime.datetime.utcnow(),
               'email': user_data['email']}
    LOG.info("payload type %s" % type(payload))
    token=jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    LOG.info("in get_jwt token type %s" % type(token))
    return token


if __name__ == '__main__':
    APP.run(host='127.0.0.1', port=5000, debug=True)
