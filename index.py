# needs mongodb (not needed anymore, but could help)
# needs python modules: pymongo, flask

import datetime

from flask import Flask, session, redirect, url_for, escape, render_template, request
from simplekv.memory import DictStore
from flask.ext.kvsession import KVSessionExtension
from datetime import timedelta
from forms.login_form import LoginForm
from forms.create_account_form import CreateAccountForm
from forms.public_key_form import PublicKeyUpload
from forms.recover_password_form import RecoverPasswordForm
from forms.parameters_form import ParametersForm
from forms.update_password_form import UpdatePasswordForm


# a DictStore will store everything in memory
# could try MemcacheStore as well
store = DictStore()

app = Flask(__name__)
app.secret_key = 'd"\xdd\x99K9\x89_g\xd5+H\xdf!g\x92\xa4\x89\xdc\'<\x1e\xcd\x14'
app.config.from_envvar('SESSION_COOKIE_SECURE', True)
app.debug=False

KVSessionExtension(store, app)

from login import *

_TOKENS = dict()
_TRIES = dict()

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=60)


# default index, login page
@app.route("/")
def redirect_to_login():
    if 'username' in session:
        return redirect("/logged_in")
    else:
        return redirect("/login")


# login
@app.route("/login")
def login_page():
    form = LoginForm()
    return render_template("login.html", form=form)


# login POST logic
@app.route("/login", methods=['POST'])
def login():
    form = LoginForm(request.form)
    if not form.validate_on_submit():
        form = LoginForm()
        return render_template("login.html", form=form, msg="Form not valid")
    
    user = dict()
    # data and make sure to strip any accidental blank spaces.
    # Courteous and simple
    user['username'] = request.form['username'].lstrip().rstrip()
    user['password'] = request.form['password'].lstrip().rstrip()

    # if user is valid, log him in
    # of course anyone could access that page but sessions are not in the scope of this
    # assignment

    if user['username'] not in _TRIES:
        _TRIES[user['username']] = {'timestamp': datetime.datetime.now(), 'tries': 0}

    if _TRIES[user['username']]['timestamp'] < (datetime.datetime.now()-datetime.timedelta(minutes=5)):
        _TRIES[user['username']]['tries'] = 0
        _TRIES[user['username']]['timestamp'] = datetime.datetime.now()

    if _TRIES[user['username']]['tries'] >= 30:
        return render_template("login.html", msg="Too many attempts in past 5 minutes, "
                                                 "try again later", form=form)

    if check_user(user):
        _TRIES[user['username']]['tries'] = 0
        session['username'] = request.form['username'].lstrip().rstrip()
        return redirect(url_for(".logged_in_page"))
    else:
        _TRIES[user['username']]['tries'] += 1
        return render_template("login.html", msg="Invalid user name or password", form=form)


@app.route("/create_account")
def create_account_page():
    form = CreateAccountForm()
    return render_template("create_account.html", form=form)


@app.route("/create_account", methods=['POST'])
def create_account():
    form = CreateAccountForm(request.form)
    if not form.validate_on_submit():
        form = CreateAccountForm()
        return render_template("create_account.html", form=form, msg="Form not valid")
    
    user_name = ""
    user_exists = ""
    incorrect_password = ""
    email = ""
    age = ""
    name = ""

    if int(request.form['Age']) < 0 or int(request.form['Age'])> 150:
        age = "Not a valid age"
    
    if len(request.form['Name']) > 30:
        name = request.form['Name'][0:30]
    else:
        name = request.form['Name']

    # check if email is valid, simple check
    if not any(x == "@" for x in request.form['Email']):
        email = "Not an email address"
    elif does_email_exist(request.form['Email']):
        # check if email is already associated with account
        email = "Email already entered"

    # check if user name
    if len(request.form['User']) == 0:
        # exists
        user_exists = "Need a user name"
    elif len(request.form['User']) < 6:
        # longer than 6 characters
        user_exists = "Please enter a user name longer than 5 characters"
    elif does_username_exist(request.form['User']):
        user_exists = "User name already taken"
    else:
        user_name = request.form['User']

    # check password
    if not check_password(request.form['Password']):
        incorrect_password = "Password doesn't meet requirements"

    # confirm password
    if request.form['Password'] != request.form['Confirm_Password']:
        incorrect_password = "Passwords don't match"


    if user_exists != "" or incorrect_password != "" or email != "" or age != "":
        return render_template("create_account.html", user_exists=user_exists,
                               incorrect_password=incorrect_password, age=age, form=form)
    else:
        # Create user
        user = dict()
        user["username"] = request.form['User'].lstrip().rstrip()
        user['password'] = request.form['Password'].lstrip().rstrip()
        user['email'] = request.form['Email'].rstrip().lstrip()
        user['name'] = name
        user['age'] = int(request.form['Age'])

        token = generate_token(20)
        _TOKENS[token] = {'timestamp': datetime.datetime.now(), 'user': create_password(user)}

        app.add_url_rule('/'+token, "confirm_user", confirm_user)

        msg = "Username: " + user['username'] +", Confirm account link: " + request.url_root + token
        send_email(user['email'], "Confirm Account", msg)

        return redirect(url_for(".please_confirm_page", email=user['email']))


def confirm_user():
    token = request.url.split("/")[-1]
    # make sure token exists
    if token in _TOKENS:
        # make sure timeout hasn't been reached
        if _TOKENS[token]['timestamp'] > (datetime.datetime.now()-datetime.timedelta(minutes=60)):
            user = _TOKENS[token]['user']
            if not does_email_exist(user['email']) and not does_username_exist(user['username']):
                create_user(_TOKENS[token]['user'])
                del _TOKENS[token]
                return render_template("email_confirmed.html")
            else:
                del _TOKENS[token]
                return render_template('login.html', msg="User name or password already taken")
        else:
            del _TOKENS[token]
            return redirect("/timeout")
    return redirect("/login")


@app.route("/please_confirm")
def please_confirm_page():
    return render_template("please_confirm.html", email=request.args['email'])

@app.route("/email_sent")
def email_sent_page():
    return render_template("info_sent.html", email=request.args['email'])


@app.route("/logged_in")
def logged_in_page():
    if 'username' in session:
        username = session['username']
        keys = database_wrapper.get_public_keys(username)
        author = "Nicolas Primeau"
        form = PublicKeyUpload()
        return render_template("logged_in.html", author=author, msg="", keys=keys, form=form)
    else:
        return redirect("/login")


@app.route("/logged_in", methods=['POST'])
def logged_in():
    form = PublicKeyUpload()
    if 'username' in session:
        key = request.form['public_key'].lstrip().rstrip()
        msg=""
        author = "Nicolas Primeau"
        username = session['username']
        if key != "" and form.validate_on_submit():
            database_wrapper.store_public_key(key, username)
            msg = "Key saved successfully"

        keys = database_wrapper.get_public_keys(username)

        return render_template("logged_in.html", form=form, author=author, msg=msg, keys=keys)
    else:
        return redirect("/login")

@app.route("/logout")
def logout():
    session.pop('username', None)
    return redirect("/login")


@app.route("/info_retrieval")
def forgot_info_page():
    return render_template("info_retrieval.html")


# if user lost password
@app.route("/info_retrieval", methods=['POST'])
def forgot_info():
    if request.form['Email'] == "":
        msg_warning = "Please provide the email associated with account"
        return render_template("info_retrieval.html", msg_warning=msg_warning)
    token = retrieve_password(request.form['Email'], request.url_root)
    if token is None:
        return redirect(url_for(".email_sent_page", email=request.form['Email']))

    # generate token which is the link to the password retrieval page
    # this token is a string of 30 random characters from lower case, upper case and digits
    # and has a timeout of 15 mins.

    _TOKENS[token] = {'email': request.form['Email'], 'timestamp': datetime.datetime.now()}

    # change_pass.methods = ['POST']

    # add token to possible urls
    app.add_url_rule('/'+token, "change_password_page", change_password_page)
    app.add_url_rule('/'+token, "change_pass", change_pass, methods=["POST"])

    return redirect(url_for(".email_sent_page", email=request.form['Email']))


@app.route("/password_update", methods=['GET'])
def update_password_page():
    if 'username' in session:
        form = UpdatePasswordForm()
        return render_template("password_update.html", form=form)
    else:
        return redirect("/login")
        


@app.route("/password_update", methods=['POST'])
def update_password():
    if 'username' in session:
        form = UpdatePasswordForm()
        if not form.validate_on_submit():
            return render_template("password_update.html", form=form, pass_warning="Invalid Form")
            
            
        incorrect_password = ""

        user = dict()

        user['username'] = session['username']
        user = database_wrapper.get_user_by_username(user['username'])
        user['password'] = request.form['old_password'].lstrip().rstrip()

        if not check_user(user):
            incorrect_password = "Old password is incorrect"

        if not check_password(request.form['Password']):
            incorrect_password = "Password doesn't meet requirements"
        elif request.form['Password'] != request.form['Confirm_Password']:
            incorrect_password = "Passwords don't match"

        if incorrect_password != "":
            return render_template("password_update.html", pass_warning=incorrect_password)
            
        user['password'] = request.form['Password'].lstrip().rstrip()
        
        change_password(user)
        return render_template("password_update.html", form=form,
                                pass_warning="Password successfully changed")
    else:
        return redirect("/login") 
    

@app.route("/timeout")
def timeout_page():
    return render_template("timeout.html")


@app.route("/parameters", methods=['GET'])
def parameters_get():
    if 'username' in session:
        form = ParametersForm()
        username = session['username']
        user = database_wrapper.get_user_by_username(username)
        if 'name' in user:
            name = user['name']
        else:
            name = ""
        if 'age' in user:
            age = user['age']
        else:
            age = ''

        if 'access list' not in user:
            user['access list'] = list()
            user['access list'].append(username)
            database_wrapper.update_user(user)

        usernames = list()
        for us in database_wrapper.get_all_usernames():
            if us in user['access list'] and us != username:
                usernames.append((us, True))
            elif us != username:
                usernames.append((us, False))


        return render_template("parameters.html", form=form,name=name, age=age, names=usernames)
    else:
        return redirect("/login")


@app.route("/parameters", methods=['POST'])
def parameters_post():
    if 'username' in session:
        form = ParametersForm()
        if not form.validate_on_submit():
            return render_template("parameters.html",msg="Not valid form", form=form)
        
        username = session['username']
        user = database_wrapper.get_user_by_username(username)
        user['name'] = request.form['name']
        user['age'] = int(request.form['age'])
        user['access list'] = list()

        all_usernames = database_wrapper.get_all_usernames()
        all_usernames.remove(username)
        user['access list'].append(username)
        for un in all_usernames:
            if un in request.form:
                user['access list'].append(un)

        if len(user['name']) > 40:
            user['name'] = user['name'][0:40]

        if user['age'] < 0:
            user['age'] = 0
        elif user['age'] > 150:
            user['age'] = 150


        database_wrapper.update_user(user)

        msg = "Information Updated!"

        usernames = list()
        for us in all_usernames:
            if us in user['access list'] and us != username:
                usernames.append((us, True))
            elif us != username:
                usernames.append((us, False))

        return render_template("parameters.html", form=form, name=user['name'], age=user['age'], names=usernames, msg=msg)

    else:
        return redirect("/login")


def change_password_page():
    form = RecoverPasswordForm()
    # get token
    token = request.url.split("/")[-1]
    # make sure token exists
    if token in _TOKENS:
        # make sure timeout hasn't been reached
        if _TOKENS[token]['timestamp'] > (datetime.datetime.now()-datetime.timedelta(minutes=15)):
            return render_template("change_password.html", token=token, form=form)
        else:
            del _TOKENS[token]
            return redirect("/timeout")
    return redirect("/login")


def change_pass():
    form = RecoverPasswordForm()
    if not form.validate_on_submit():
        return render_template("change_password.html", form=form, pass_warning="Invalid form")
    
    incorrect_password = ""

    if not check_password(request.form['Password']):
        incorrect_password = "Password doesn't meet requirements"
    elif request.form['Password'] != request.form['Confirm_Password']:
        incorrect_password = "Passwords don't match"

    if incorrect_password != "":
        return render_template("change_password.html", form=form, pass_warning=incorrect_password)

    token = request.url.split("/")[-1]
    user = dict()
    user['email'] = _TOKENS[token]['email'].lstrip().rstrip()
    user['password'] = request.form['Password'].lstrip().rstrip()
    change_password(user)
    # delete token out of TOKENS, change password page can not be accessed anymore
    del _TOKENS[token]
    # make user login
    return redirect("/login")

if __name__ == '__main__':
    app.run()
