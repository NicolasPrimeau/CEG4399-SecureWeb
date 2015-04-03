__author__ = 'Nixon'

import urllib
from urllib import parse

fn = "sensitive_data"


def get_db_ip():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_IP" in line:
            return line.split(" ")[-1]


def get_db_port():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_PORT" in line:
            return int(line.split(" ")[-1])


def get_db_user():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_user" in line:
            return line.split(" ")[-1]


def get_db_name():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_DB" in line:
            return line.split(" ")[-1]

def get_db_password():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "mongo_password" in line:
            return urllib.parse.quote_plus(line.split(" ")[-1])


def get_email_user():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "email_username" in line:
            return line.split(" ")[-1]

def get_email_password():
    lines = [line.strip() for line in open(fn)]
    for line in lines:
        if "email_password" in line:
            return line.split(" ")[-1]
