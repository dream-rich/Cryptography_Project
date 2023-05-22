from flask import Flask, render_template
from website import create_app
from flask_login import current_user
from crypto import generate_keys, derive_shared_key
import requests

app = create_app()

@app.route("/")
def sign_up():
    user = {'is_authenticated': True}
    return render_template("sign_up.html", user = user)

@app.route('/exchange_keys', methods=['POST'])
def exchange_keys():
    global client_public_key

    client_public_key = request.json['public_key']

    server_private_key, server_public_key = generate_keys()

    shared_key = derive_shared_key(server_private_key, client_public_key)

    return jsonify({'shared_key': shared_key})

   
if __name__ == '__main__':
    app.run(debug=True)

