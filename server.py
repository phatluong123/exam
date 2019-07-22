from flask import Flask, render_template, request, redirect, session, flash
import re, datetime
from mysqlconnection import connectToMySQL
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key='alo'
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
password_regex = re.compile(r'^(?=.*[\d])(?=.*[A-Z])(?=.*[a-z])(?=.*[@#$])[\w\d@#$]+$')


@app.route("/")
def index():
    return render_template("registration_login.html")


@app.route('/register', methods=['POST'])
def add_info():
    is_valid = True
    if len(request.form['first_name']) < 2:
        flash("First name at least 2 characters",  'first')
        is_valid = False
    if len(request.form['last_name']) < 2:
        flash("Last name at least 2 characters",'last')
        is_valid = False
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid email, please re-enter", 'email_error')
        is_valid = False
    email=request.form['email']
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {"email": request.form["email"]}
    mysql = connectToMySQL('handy_helper')
    users_email=mysql.query_db(query, data)
    count=0
    for user_email in users_email:
        print(user_email)
        if user_email['email'] == email:
            count+=1
    if count==0:
        pass
    if count!=0:
        flash("email exist", 'email_error')
        is_valid = False
    if len(request.form['password1']) < 8:
        flash("Password at least 8 character", 'password1')
        is_valid = False
    # if not password_regex.match(request.form['password1']):
    #     flash("Password at least 8 characters and must have 1 Upper case, 1 Lower case, 1 special (@#$), and 1 digit ", 'password1')
    #     is_valid = False
    if (request.form['password1']) != (request.form['password2']):
        flash("Password not match", 'password2')
        is_valid = False
    if not is_valid:
        return redirect("/")
    else:

        pw_hash = bcrypt.generate_password_hash(request.form['password1'])
        data = {
            'fn': request.form['first_name'],
            'ln': request.form['last_name'],
            'email': request.form['email'],
            'pw_hash': pw_hash
        }
        query='INSERT INTO users(first_name, last_name, email, pw_hash) VALUES (%(fn)s, %(ln)s, %(email)s, %(pw_hash)s )'
        mysql=connectToMySQL('handy_helper')
        user_id = mysql.query_db(query, data)
        session['user_id']=user_id
        return redirect('/logged')


@app.route('/login', methods=['POST'])
def logged_in():
    mysql = connectToMySQL('handy_helper')
    query = "SELECT * FROM users WHERE email = %(email)s;"
    data = {"email": request.form["login_email"]}
    result = mysql.query_db(query, data)
    if len(result) > 0:
        if bcrypt.check_password_hash(result[0]['pw_hash'], request.form['login_password']):
            session['user_id'] = result[0]['id']
            return redirect('/logged')
    else :
        flash('Email or password wrong', 'login_error')
        return redirect("/")

@app.route('/logged')
def success_log_in():
    user_id = session['user_id']
    query = (f'SELECT first_name from users where id ={user_id}')
    mysql = connectToMySQL('handy_helper')
    user = mysql.query_db(query)
    user = user[0]['first_name']
    query = 'select * from jobs order by created_at desc'
    mysql = connectToMySQL('handy_helper')
    jobs = mysql.query_db(query)
    query = (f'select * from jobs where work_id ={user_id}')
    mysql = connectToMySQL('handy_helper')
    user_jobs = mysql.query_db(query)
    print(user_jobs,' user jon')
    return render_template('logged.html',user=user, jobs=jobs, user_jobs=user_jobs)


@app.route('/add/<job_id>')
def add_job(job_id):
    print('job _id',job_id)
    user_id = session['user_id']
    query = f' UPDATE jobs SET work_id ={user_id} where id ={job_id}'
    mysql = connectToMySQL('handy_helper')
    mysql.query_db(query)
    return redirect('/logged')


@app.route('/remove/<job_id>')
def delete_job(job_id):
    query = f' delete from job_category where job_id ={job_id}'
    mysql = connectToMySQL('handy_helper')
    mysql.query_db(query)
    query = f' delete from jobs where id ={job_id}'
    mysql = connectToMySQL('handy_helper')
    mysql.query_db(query)

    return redirect('/logged')


@app.route('/giveup/<job_id>')
def giveup_job(job_id):
    query = f' UPDATE jobs SET work_id = NULL WHERE id  ={job_id}'
    mysql = connectToMySQL('handy_helper')
    mysql.query_db(query)
    return redirect('/logged')


@app.route('/jobs/new')
def new_job():
    user_id = session['user_id']
    query = (f'SELECT first_name from users where id ={user_id}')
    mysql = connectToMySQL('handy_helper')
    user = mysql.query_db(query)
    user = user[0]['first_name']
    query = 'SELECT * from category'
    mysql = connectToMySQL('handy_helper')
    categories = mysql.query_db(query)
    return render_template('newjob.html', user=user, categories=categories)


@app.route('/jobs/new/process', methods=['POST'])
def add_new_job():
    is_valid = True
    if len(request.form['title']) < 3:
        flash("First name at least 3 characters",  'title')
        is_valid = False
    if len(request.form['description']) < 5:
        flash("description at least 5 characters",'description')
        is_valid = False
    if len(request.form['location']) < 2:
        flash("Location at least 2 character", 'location')
        is_valid = False
    if not is_valid:
        return redirect("/jobs/new")
    else:
        data1 = {
            'title': request.form['title'],
            'description': request.form['description'],
            'location': request.form['location'],
            'create_id': session['user_id']
        }
        query='INSERT INTO jobs(title, description, location, create_id) VALUES (%(title)s, %(description)s, %(location)s, %(create_id)s )'
        mysql=connectToMySQL('handy_helper')
        new_job_id=mysql.query_db(query, data1)
        category2=request.form['category2']
        categories1 = request.form.getlist('category1')
        if len(category2)>0:
            data={
                'new_type':category2
            }
            query = f'INSERT INTO category(type) VALUES (%(new_type)s)'
            mysql = connectToMySQL('handy_helper')
            new_category=mysql.query_db(query, data)
            print('new typre', new_category)
            data1={
                'job_id':new_job_id,
                'new_type':new_category
            }
            query = 'INSERT INTO job_category(job_id, category_id) VALUES (%(job_id)s, %(new_type)s)'
            mysql = connectToMySQL('handy_helper')
            mysql.query_db(query, data1)

        if len(category2)<1:
            pass
        if len(categories1)>0:
            for category in categories1:
                data3={
                    'job_id':new_job_id,
                    'new_type':category
                }
                query = 'INSERT INTO job_category(job_id, category_id) VALUES (%(job_id)s, %(new_type)s)'
                mysql = connectToMySQL('handy_helper')
                mysql.query_db(query, data3)
        # print('category2', category2)
        # print('len of category2', len(category2))
        # print('category1', categories1)
        return redirect('/logged')


@app.route('/jobs/edit/<job_id>')
def edit_job(job_id):
    user_id = session['user_id']
    query = (f'SELECT first_name from users where id ={user_id}')
    mysql = connectToMySQL('handy_helper')
    user = mysql.query_db(query)
    user = user[0]['first_name']
    query = (f'SELECT * from jobs where id ={job_id}')
    mysql = connectToMySQL('handy_helper')
    job = mysql.query_db(query)
    return render_template('edit.html', user=user, job=job)


@app.route('/jobs/edit/<job_id>/process', methods=['POST'])
def edit_job_job(job_id):
    is_valid = True
    if len(request.form['title']) < 3:
        flash("First name at least 3 characters",  'title')
        is_valid = False
    if len(request.form['description']) < 5:
        flash("description at least 5 characters",'description')
        is_valid = False
    if len(request.form['location']) < 2:
        flash("Location at least 2 character", 'location')
        is_valid = False
    if not is_valid:
        return redirect(f"/jobs/edit/{job_id}")
    else:
        data = {
            'title': request.form['title'],
            'description': request.form['description'],
            'location': request.form['location'],
            'create_id': session['user_id']
        }
        query=f'UPDATE jobs SET title =%(title)s, description= %(description)s, location = %(location)s where id={job_id}'
        mysql=connectToMySQL('handy_helper')
        mysql.query_db(query, data)
        return redirect('/logged')


@app.route('/jobs/<job_id>')
def views_job(job_id):
    user_id = session['user_id']
    query = (f'SELECT first_name from users where id ={user_id}')
    mysql = connectToMySQL('handy_helper')
    user = mysql.query_db(query)
    user = user[0]['first_name']
    query = f'select * from jobs where id = {job_id}'
    mysql = connectToMySQL('handy_helper')
    job = mysql.query_db(query)
    query = f'select category.type, job_category.job_id, job_category.category_id, jobs.title from jobs ' \
        f'left join job_category on jobs.id = job_category.job_id ' \
        f'join category on category.id = job_category.category_id where job_id ={job_id}'
    mysql = connectToMySQL('handy_helper')
    categories = mysql.query_db(query)
    return render_template('views.html',user=user, job=job, categories =categories )











@app.route('/logout')
def logout():
    session['user_id']=None
    return redirect('/')



if __name__ == "__main__":
    app.run(debug=True)


