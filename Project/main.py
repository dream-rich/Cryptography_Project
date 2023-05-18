from flask import Flask, render_template
from website import create_app

app = create_app()

@app.route("/")
def sign_up():
    user = {"username": "Hong Nhung"}
    return render_template("sign_up.html", user = user)

if __name__ == '__main__':
    app.run(debug=True)

