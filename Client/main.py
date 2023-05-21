from flask import Flask, render_template, redirect, url_for
from website import create_app
from flask_login import current_user

app = create_app()

@app.route('/', methods=['GET', 'POST'])
def login():
    return redirect(url_for('auth.login'))

if __name__ == '__main__':
    app.run(debug=True)

