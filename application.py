import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from datetime import datetime

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///blog.db")


@app.route("/")
@login_required
def index():
    """Display blog"""


    return render_template("index.html")


@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""

    if request.method == "GET":

        # get username from web form
        username = request.args.get("username")

        # check that username is longer than 1, then pull list from DB to check against
        if len(username) > 1:
            usernames = db.execute("SELECT username FROM users")

        # return false if username is available
        if username in [elem["username"] for elem in usernames]:
            return jsonify(False)

        # return true if username is NOT available
        else:
            return jsonify(True)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        session["username"] = rows[0]["username"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":

        # check for username
        if not request.form.get("username"):
            return apology("must provide a username", 400)

        # check for password
        elif not request.form.get("password"):
            return apology("must provide a password", 400)

        # check for confirmation
        elif not request.form.get("confirmation"):
            return apology("must confirm password", 400)

        # check that password and confirmation match
        elif request.form.get("password") != request.form.get("confirmation"):
            return apology("password and confirmation must be the same", 400)

        hash = generate_password_hash(request.form.get("password"), method='pbkdf2:sha256', salt_length=8)

        result = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)",
            username=request.form.get("username"), hash=hash)

        if not result:
            return apology("username already exists!", 400)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # remember the username of the user logged in
        session["username"] = rows[0]["username"]

        # Redirect user to blog post page
        flash("Registered!", "success")
        return render_template("index.html")

    else:
        return render_template("register.html")

@app.route("/post_blog", methods=["POST"])
def post_blog():
    """post a blog written by the user"""

    # capture date, time blog is posted
    created = datetime.now()

    # enter blog post into DB
    entry = db.execute("INSERT INTO blogs (username, title, content, created) VALUES(:username, :title, :content, :created)",
                        username = session["username"], title=request.form.get("blog_title"), content=request.form.get("blog_post"), created=created)

    # retrieve previous blog posts from users for display
    data = db.execute("SELECT * FROM blogs WHERE username=:username", username=session["username"])

    # show a message to confirm blog was posted
    flash("Posted!", "success")

    # return index.html
    return render_template("index.html", data = data)

@app.route("/search", methods=["GET", "POST"])
def search():

    data = db.execute("SELECT * FROM blogs WHERE (username=:username)", username=request.form.get("username"))
    return render_template("search_results.html", data = data)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
