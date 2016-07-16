from flask import Flask, request, redirect, render_template, flash, session
import re
from flask_bcrypt import Bcrypt
from mysqlconnection import MySQLConnector

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9\.\+_-]+@[a-zA-Z0-9\._-]+\.[a-zA-Z]*$')
app=Flask(__name__)
mysql = MySQLConnector(app, 'wall')
bcrypt = Bcrypt(app)
app.secret_key='wall'

@app.route('/')
def index():
	return render_template('index_home.html')

@app.route('/register', methods=['POST'])
def create_user():
	hasError = False
	#collect form fields
	first_name = request.form['first-name']
	last_name = request.form['last-name']
	email = request.form['email']
	password = request.form['password']
	confirm_password = request.form['confirm-password']
	#validate first name
	if len(first_name) < 2 or not first_name.isalpha():
		flash("Invalid first name")
		hasError = True
	if len(last_name) < 2 or not last_name.isalpha():
		flash("Invalid last name")
		hasError = True
	if not EMAIL_REGEX.match(email) or len(email) < 1:
		flash("Invalid email address")
		hasError = True
	if len(password) < 8:
		flash("Password must be at least 8 characters")
		hasError = True
	if password != confirm_password:
		flash("Passwords do not match")
		hasError = True
	if hasError:
		return redirect('/')
	else:
		#check if user exists
		check_query = 'SELECT email FROM users WHERE email=:email'
		check_data = {'email': email}
		check_result = mysql.query_db(check_query, check_data)
		if check_result:
			flash("User with entered email already exists")
			return redirect('/')
		#add user
		pw_hash = bcrypt.generate_password_hash(password)
		query = 'INSERT INTO users (first_name, last_name, email, pw_hash, created_at, updated_at) VALUES (:first_name, :last_name, :email, :pw_hash, NOW(), NOW())'
		data={'first_name': first_name, 'last_name': last_name, 'email': email, 'pw_hash': pw_hash}
		mysql.query_db(query, data)
		return redirect('/wall')

@app.route('/login', methods=['POST'])
def login():
	#extract info from form
	email = request.form['email']
	password = request.form['password']
	#check if user exists
	check_query = 'SELECT * FROM users WHERE email=:email'
	check_data = {'email': email}
	check_result = mysql.query_db(check_query, check_data)
	if check_result:
		#check password
		if bcrypt.check_password_hash(check_result[0]['pw_hash'], password):
			session['id'] = check_result[0]['id']
			return redirect('/wall')
		else:
			flash("Incorrect password for given email")
			return redirect('/')
	else:
		flash("User does not exist")
		return redirect('/')

@app.route('/wall')
def show():
	if 'id' not in session:
		return redirect('/')
	user_query = 'SELECT * FROM users WHERE id=:id'
	user_data = {'id': session['id']}
	user = mysql.query_db(user_query, user_data)

	message_query = 'SELECT first_name, last_name, message, messages.created_at, messages.id FROM users JOIN messages ON users.id=messages.user_id ORDER BY messages.created_at DESC'
	messages = mysql.query_db(message_query)
	
	name = user[0]['first_name']

	comment_query = 'SELECT first_name, last_name, comment, comments.created_at, comments.message_id FROM users JOIN comments ON users.id=comments.user_id ORDER BY comments.created_at DESC'
	comments = mysql.query_db(comment_query)

	return render_template('index_wall.html', name=name, messages=messages, comments=comments)

@app.route('/message', methods=['POST'])
def create_message():
	message = request.form['message']

	message_query = 'INSERT INTO messages (message, created_at, updated_at, user_id) VALUES (:message, NOW(), NOW(), :id)'
	message_data = {'message': message, 'id': session['id']}
	mysql.query_db(message_query, message_data)

	return redirect('/wall')

@app.route('/comment', methods=['POST'])
def create_comment():
	comment = request.form['comment']

	comment_query = 'INSERT INTO comments (comment, created_at, updated_at, message_id, user_id) VALUES (:comment, NOW(), NOW(), :message_id, :user_id)'
	comment_data = {'comment': comment, 'message_id': request.form['message_id'], 'user_id': session['id']}
	mysql.query_db(comment_query, comment_data)

	return redirect('/wall')

@app.route('/logout')
def logout():
	session.pop('id')
	return redirect('/')

app.run(debug=True)