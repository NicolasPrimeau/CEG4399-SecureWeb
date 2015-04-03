from pymongo import MongoClient
import sensitive_data


# change these settings below for local database
# --

IP = sensitive_data.get_db_ip()
PORT = sensitive_data.get_db_port()
mongo_user = sensitive_data.get_db_user()
mongo_password = sensitive_data.get_db_password()
DB = sensitive_data.get_db_name()


def add_user(user):
    client = MongoClient(IP, PORT)
    db = client[DB]
    users = db.users
    client[DB].authenticate(mongo_user, mongo_password)
    user['access list'] = list()
    user['access list'].append(user['username'])
    users.insert(user)
    client.close()


def get_user_by_username(name):
    client = MongoClient(IP, PORT)
    db = client[DB]
    users = db.users
    client[DB].authenticate(mongo_user, mongo_password)
    ret = []
    for user in users.find({'username': name}):
        ret.append(user)
    client.close()
    if len(ret) > 0:
        return ret[0]
    else:
        return None


def update_user(user):
    client = MongoClient(IP, PORT)
    db = client[DB]
    users = db.users
    client[DB].authenticate(mongo_user, mongo_password)
    #users.update({'email': user['email']},
    #             {"$set": {'password': user['password'],
    #              'salt': user['salt']}}, upsert=False)
    users.update({'email': user['email']}, user, upsert=False)
    client.close()


def get_all_usernames():
    client = MongoClient(IP, PORT)
    db = client[DB]
    users = db.users
    client[DB].authenticate(mongo_user, mongo_password)
    ret = []
    for user in users.find():
        ret.append(user['username'])
    client.close()
    if len(ret) > 0:
        return ret
    else:
        return None


def create_access_list(org_user):
    all_usernames = get_all_usernames()
    if all_usernames is None:
        return list()

    access_list = list()

    for user in all_usernames:
        if org_user in get_user_by_username(user)['access list']:
            access_list.append(user)

    return access_list

def get_user_by_email(email):
    client = MongoClient(IP, PORT)
    db = client[DB]
    users = db.users
    client[DB].authenticate(mongo_user, mongo_password)
    ret = []
    for user in users.find({'email': email}):
        ret.append(user)
    client.close()
    if len(ret) > 0:
        return ret[0]
    else:
        return None


def store_public_key(key, user):
    client = MongoClient(IP, PORT)
    db = client[DB]
    client[DB].authenticate(mongo_user, mongo_password)
    temp = dict()
    temp['public_key'] = key
    temp['username'] = user
    db.public_keys.update({'username': user}, temp, upsert=True)
    client.close()


def get_public_keys(username):
    client = MongoClient(IP, PORT)
    db = client[DB]
    client[DB].authenticate(mongo_user, mongo_password)
    ret = list()
    if db.public_keys.count() == 0:
        return list()

    access_list = create_access_list(username)

    for r in db.public_keys.find():
        if r['username'] in access_list:
            ret.append(r)

    client.close()
    return ret

