# needs mongodb (not needed anymore, but could help)
# needs python modules: pymongo, flask

import datetime

from flask import Flask, session, redirect, url_for, escape, render_template, request


app = Flask(__name__)
app.secret_key = 'd"\xdd\x99K9\x89_g\xd5+H\xdf!g\x92\xa4\x89\xdc\'<\x1e\xcd\x14'
app.config.from_envvar('SESSION_COOKIE_SECURE', True)

from login import *

_TOKENS = dict()
_TRIES = dict()


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
    return render_template("login.html")


# login POST logic
@app.route("/login", methods=['POST'])
def login():
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
                                                 "try again later", user=user['username'])

    if check_user(user):
        _TRIES[user['username']]['tries'] = 0
        session['username'] = request.form['username'].lstrip().rstrip()
        return redirect(url_for(".logged_in_page"))
    else:
        _TRIES[user['username']]['tries'] += 1
        return render_template("login.html", msg="Invalid user name or password",user=user['username'])


@app.route("/create_account")
def create_account_page():
    return render_template("create_account.html")


@app.route("/create_account", methods=['POST'])
def create_account():
    user_name = ""
    user_exists = ""
    incorrect_password = ""
    email = ""

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

    if user_exists != "" or incorrect_password != "" or email != "":
        return render_template("create_account.html", user_name=user_name, user_exists=user_exists,
                               incorrect_password=incorrect_password, email=email)
    else:
        # Create user
        user = dict()
        user["username"] = request.form['User'].lstrip().rstrip()
        user['password'] = request.form['Password'].lstrip().rstrip()
        user['email'] = request.form['Email'].rstrip().lstrip()

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
        return render_template("logged_in.html", user=username, author=author, msg="", keys=keys)
    else:
        return redirect("/login")


@app.route("/logged_in", methods=['POST'])
def logged_in():
    if 'username' in session:
        key = request.form['public_key'].lstrip().rstrip()
        msg=""
        author = "Nicolas Primeau"
        username = session['username']
        if key != "":
            database_wrapper.store_public_key(key, username)
            msg = "Key saved successfully"

        keys = database_wrapper.get_public_keys(username)

        return render_template("logged_in.html", user=username, author=author, msg=msg, keys=keys)
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


@app.route("/timeout")
def timeout_page():
    return render_template("timeout.html")


@app.route("/parameters", methods=['GET'])
def parameters_get():
    if 'username' in session:
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


        return render_template("parameters.html", name=name, age=age, names=usernames)
    else:
        return redirect("/login")


@app.route("/parameters", methods=['POST'])
def parameters_post():
    if 'username' in session:
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

        return render_template("parameters.html", name=user['name'], age=user['age'], names=usernames, msg=msg)

    else:
        return redirect("/login")


def change_password_page():
    # get token
    token = request.url.split("/")[-1]
    # make sure token exists
    if token in _TOKENS:
        # make sure timeout hasn't been reached
        if _TOKENS[token]['timestamp'] > (datetime.datetime.now()-datetime.timedelta(minutes=15)):
            return render_template("change_password.html", token=token)
        else:
            del _TOKENS[token]
            return redirect("/timeout")
    return redirect("/login")


def change_pass():
    incorrect_password = ""

    if not check_password(request.form['Password']):
        incorrect_password = "Password doesn't meet requirements"
    elif request.form['Password'] != request.form['Confirm_Password']:
        incorrect_password = "Passwords don't match"

    if incorrect_password != "":
        return render_template("change_password.html", pass_warning=incorrect_password)

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