import database_wrapper
import hashlib
import random
import smtplib
import string
import sensitive_data

username = sensitive_data.get_email_user()
password = sensitive_data.get_email_password()


def check_user(user):
    # check if 1, user exists and 2, password is good
    user2 = database_wrapper.get_user_by_username(user['username'])
    if user2 is not None:
        return user2['password'] == compute_password(user['password'], user2['salt'])
    return False


def generate_token(length=60):
    return ''.join(random.SystemRandom().choice(string.ascii_lowercase +
                                                string.ascii_uppercase + string.digits) for _ in range(60))


def check_password(password):
    # a bunch of password requirements
    if len(password) < 8:
        return False

    if not any(x.isupper() for x in password):
        return False

    if not any(x.islower() for x in password):
        return False

    if not any(x.isdigit() for x in password):
        return False

    #characters = ['!', '@', '#', '$', '%', '^', '&', '*']

    #if not any(x in characters for x in password):
    #    return False

    return True


def compute_password(pwd, salt):
    return hashlib.sha512((pwd+salt).encode()).hexdigest()


def does_username_exist(name):
    user = database_wrapper.get_user_by_username(name)
    return user is not None


def does_email_exist(email):
    user = database_wrapper.get_user_by_email(email)
    return user is not None


def create_password(user):
    user['salt'] = ''.join(random.SystemRandom().choice(string.ascii_lowercase +
                                                        string.ascii_uppercase + string.digits) for _ in range(30))
    user['password'] = compute_password(user['password'], user['salt'])
    return user


def create_user(user):
    database_wrapper.add_user(user)

def change_password(user):
    user['salt'] = ''.join(random.SystemRandom().choice(string.ascii_lowercase +
                                                        string.ascii_uppercase + string.digits) for _ in range(30))
    user['password'] = compute_password(user['password'], user['salt'])
    database_wrapper.update_user(user)


def send_email(email, subject, message):
    server = smtplib.SMTP('smtp.gmail.com:587')
    server.ehlo()
    server.starttls()
    server.login(username, password)
    msg = "\r\n".join([
      "From: " + username,
      "To: "+email,
      "Subject: " + subject,
      "",
      message
      ])
    server.sendmail(username, email, msg)
    server.quit()


def retrieve_password(email, base_url):
    user = database_wrapper.get_user_by_email(email)
    if user is not None:
        token = generate_token()

        # NOTICE
        # Normally a production server would have it's own stmp server
        # and we wouldn't have this information below. In this setting
        # in order for it to work cross platform, and in the spirit of
        # easy setup, gmail was chosen

        # also, sending the username by email isn't very good since a man
        # in the middle attack could read it. However, gmail encrypts every
        # email by default so this isn't a concern by using gmail.
        # This encryption is necessary
        msg = "Username: " + user['username'] +", Recover password link: " + base_url + token
        send_email(email, "Password Recovery", msg)

        return token

    return None

