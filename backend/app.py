#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os

from keycloak import KeycloakOpenID

from flask import Flask, jsonify, request

app = Flask(__name__)

KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "http://keycloak/auth/")
KEYCLOAK_REALM_NAME = os.getenv("KEYCLOAK_REALM_NAME", "user-dev")

KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "client-service")
KEYCLOAK_CLIENT_SECRET_KEY = os.getenv("KEYCLOAK_CLIENT_SECRET_KEY", "")


@app.route('/reports', methods=['GET', 'POST'])
def hello_world():
    token = request.headers['authorization']
    response = jsonify({'token': token})
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add("Access-Control-Allow-Headers", "DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization")
    response.headers.add("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
    return response


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
