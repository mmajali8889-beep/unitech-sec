import os, subprocess, sqlite3, pickle, hashlib
from flask import Flask, request, redirect

app = Flask(__name__)
app.config["SECRET_KEY"] = "changeme"
DB_PASSWORD = "Sup3rS3cretPassw0rd!"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system("ls " + cmd)
    return "ok"

@app.route("/user/<name>")
def user(name):
    conn = sqlite3.connect("x.db")
    q = f"SELECT * FROM users WHERE name = '{name}'"
    conn.execute(q)
    return "ok"

@app.route("/safe")
def safe():
    n = int(request.args.get("n"))
    os.system("echo %d" % n)
    conn = sqlite3.connect("x.db")
    conn.execute("SELECT * FROM t WHERE id = ?", (request.args.get("id"),))
    return "ok"

@app.route("/load")
def load():
    return pickle.loads(request.data)

def h(p):
    return hashlib.md5(p.encode()).hexdigest()

if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
