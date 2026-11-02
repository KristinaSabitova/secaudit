import os
import pickle
import sqlite3
import subprocess

import requests
import yaml
from flask import Flask, redirect, render_template_string, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect("shop.db", check_same_thread=False)


@app.route("/users")
def users():
    name = request.args.get("name")
    q = "SELECT * FROM users WHERE name = '%s'" % name
    return str(db.execute(q).fetchall())


@app.route("/users/safe")
def users_safe():
    name = request.args.get("name")
    return str(db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall())


@app.route("/ping")
def ping():
    host = request.form["host"]
    return subprocess.check_output("ping -c1 " + host, shell=True)


@app.route("/ping/safe")
def ping_safe():
    host = request.form["host"]
    return subprocess.check_output(["ping", "-c1", host])


@app.route("/report")
def report():
    name = request.args.get("file")
    with open(os.path.join("reports", name)) as fh:
        return fh.read()


@app.route("/report/safe")
def report_safe():
    name = secure_filename(request.args.get("file"))
    with open(os.path.join("reports", name)) as fh:
        return fh.read()


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url, timeout=5).text


@app.route("/go")
def go():
    target = request.args.get("next")
    return redirect(target)


@app.route("/calc", methods=["POST"])
def calc():
    expr = request.form["expr"]
    return str(eval(expr))


@app.route("/import", methods=["POST"])
def import_cart():
    return str(pickle.loads(request.data))


@app.route("/import/yaml", methods=["POST"])
def import_yaml():
    return str(yaml.load(request.data, Loader=yaml.Loader))


@app.route("/hello")
def hello():
    who = request.args.get("who")
    return render_template_string("<h1>Hello " + who + "</h1>")


@app.route("/page")
def page():
    n = int(request.args.get("n"))
    os.system("echo page %d" % n)
    return "ok"


def maintenance(cmd):
    # Called only from the operator's console with a fixed command; no request input.
    os.system(cmd)
