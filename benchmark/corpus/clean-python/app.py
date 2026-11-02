import os
import subprocess
import sqlite3

import yaml
from flask import Flask, abort, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
db = sqlite3.connect("app.db", check_same_thread=False)
API_TOKEN = os.environ["API_TOKEN"]
PASSWORD = "your-password-here"


@app.route("/users")
def users():
    name = request.args.get("name")
    return str(db.execute("SELECT * FROM users WHERE name = ?", (name,)).fetchall())


@app.route("/ping")
def ping():
    host = request.form["host"]
    if not host.replace(".", "").isalnum():
        abort(400)
    return subprocess.check_output(["ping", "-c1", host])


@app.route("/report")
def report():
    name = secure_filename(request.args.get("file"))
    with open(os.path.join("reports", name)) as fh:
        return fh.read()


@app.route("/config", methods=["POST"])
def config():
    return str(yaml.safe_load(request.data))


@app.route("/page")
def page():
    n = int(request.args.get("n"))
    return "page %d" % n

# The old handler did eval(request.args["expr"]); removed in 2024.
