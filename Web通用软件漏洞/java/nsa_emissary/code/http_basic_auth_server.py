#!/usr/bin/env python3

from flask import Flask
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
auth = HTTPBasicAuth()

users = {
    "john": generate_password_hash("hello"),
    "susan": generate_password_hash("bye")
}

@auth.verify_password
def verify_password(username, password):
    print("{}:{}".format(username, password))
    if username in users and \
            check_password_hash(users.get(username), password):
        return username

@app.route('/emissary/Heartbeat.action', methods=['GET', 'POST'])
@app.route('/emissary/RegisterPeer.action', methods=['GET', 'POST'])
@app.route('/')
@auth.login_required
def index():
    username = auth.username()
    app.logger.info("{}:{}".format(username, auth.get_password(username)))
    return "{}:{}".format(username, auth.get_password(username))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

