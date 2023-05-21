from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
# from . import db
from website import db

import json

views = Blueprint('views', __name__)

@views.route('/authentication')
def auth():
    return render_template('authentication.html')
