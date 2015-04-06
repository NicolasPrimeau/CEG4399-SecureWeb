__author__ = 'Nixon'

import urllib
from urllib import parse

fn = "sensitive_data"


def get_db_ip():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_IP" in line:
            return get_info(line)


def get_db_port():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_PORT" in line:
            line = get_info(line)
            if line is not None:
                return int(line)

def get_db_user():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_user" in line:
            return get_info(line)


def get_db_name():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_DB" in line:
            return get_info(line)

def get_db_password():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_password" in line:
            line = get_info(line)
            if line is not None:
                return urllib.parse.quote_plus(line)


def get_email_user():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "email_username" in line:
            return get_info(line)

def get_email_password():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "email_password" in line:
            return get_info(line)
                
def get_info(line):
    line = line.split(" ")
    if len(line) >2:
        return line[-1]
    else:
        return None
