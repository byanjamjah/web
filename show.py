from flask import Blueprint, render_template, request, flash, jsonify
from flask_login import login_required, current_user
from init import db
import json
show = Blueprint('show', __name__)


@show.route('/login')

def login():

        return render_template('login.html')



@show.route('/', methods=['GET', 'POST'])
@login_required

def home():

        return render_template('index.html',user=current_user)
