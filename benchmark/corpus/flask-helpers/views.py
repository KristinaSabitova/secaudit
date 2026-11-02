import os
import sqlite3
import subprocess

from flask import Flask, request

app = Flask(__name__)
db = sqlite3.connect("app.db", check_same_thread=False)


def shell(cmd):
    return subprocess.check_output(cmd, shell=True)


def where_name(name):
    return "SELECT * FROM users WHERE name = '" + name + "'"


def requested_file():
    return request.args.get("file")


def archive(path):
    shell("tar czf /tmp/out.tgz " + path)


def page_number(raw):
    return int(raw)


@app.route("/ping")
def ping():
    return shell("ping -c1 " + request.args["host"])


@app.route("/users")
def users():
    q = where_name(request.args["name"])
    return str(db.execute(q).fetchall())


@app.route("/read")
def read():
    with open(os.path.join("data", requested_file())) as fh:
        return fh.read()


@app.route("/backup", methods=["POST"])
def backup():
    archive(request.form["dir"])
    return "ok"


@app.route("/page")
def page():
    n = page_number(request.args["n"])
    return shell("echo page %d" % n)


@app.route("/uptime")
def uptime():
    return shell("uptime")
