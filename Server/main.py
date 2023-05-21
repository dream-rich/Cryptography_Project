from flask import Flask, render_template
from website import create_app
from flask_login import current_user

app = create_app()

@app.route("/")
def sign_up():
    user = {'is_authenticated': True}
    return render_template("sign_up.html", user = user)


if __name__ == '__main__':
    app.run(debug=True)

