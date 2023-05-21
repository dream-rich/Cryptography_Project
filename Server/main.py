from flask import Flask, render_template
from website import create_app
from flask_login import current_user

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)

