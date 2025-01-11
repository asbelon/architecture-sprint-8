#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import os
from base64 import b64decode
from urllib.request import urlopen

import jwt
from cryptography.hazmat.primitives import serialization
from jwt import ExpiredSignatureError, DecodeError
# from keycloak import KeycloakOpenID

from flask import Flask, jsonify, request, Response

app = Flask(__name__)

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "http://keycloak/auth/")
KEYCLOAK_REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME", "user-dev")

KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "client-service")
KEYCLOAK_CLIENT_SECRET_KEY = os.getenv("KEYCLOAK_CLIENT_SECRET_KEY", "")

REACT_APP_KEYCLOAK_CLIENT_ID = os.getenv("REACT_APP_KEYCLOAK_CLIENT_ID", "")
KEYCLOAK_PUBLIC_KEY = os.getenv("KEYCLOAK_PUBLIC_KEY", "")


@app.route('/reports', methods=['GET', 'POST'])
def reports():
    jsonurl = urlopen('http://keycloak:8080/realms/reports-realm/')
    jwks = json.loads(jsonurl.read())

    key_der = b64decode(jwks["public_key"].encode())
    public_key = serialization.load_der_public_key(key_der)
    try:
        token = request.headers['authorization']
        atoken = token.split(' ')
        userinfo = jwt.decode(atoken[1], public_key, algorithms=["RS256"])
    except KeyError as e:
        return Response(status=401, headers={'WWW-Authenticate': 'Bearer error="invalid_token"'})
    except ExpiredSignatureError as e:
        return Response(status=401, headers={'WWW-Authenticate': 'Bearer error="expired_token"'})
    except DecodeError as e:
        return Response(status=401, headers={'WWW-Authenticate': 'Bearer error="invalid_token"'})

    response = jsonify({'token': token, 'userinfo': userinfo})
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add("Access-Control-Allow-Headers",
                         "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    return response


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
