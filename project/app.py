import os
import csv
import io

from cs50 import SQL
from flask import flash, Flask, redirect, render_template, request, session, jsonify, url_for
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from .helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Custom filter
# app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
if not os.path.exists("vocab.db"):
    db = SQL("sqlite:///vocab.db")
    # create tables here, or read from CSV to populate
    # db.execute("CREATE TABLE ...")
else:
    db = SQL("sqlite:///vocab.db")


def safe_strip(value):
    if isinstance(value, list):
        # If list, join with comma or take first element
        return ", ".join(value).strip()
    elif isinstance(value, str):
        return value.strip()
    else:
        # fallback for None or other types
        return ""

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@app.route("/index")
def index():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return apology("must provide username", 400)
        elif not password:
            return apology("must provide password", 400)

        confirmation = request.form.get("confirmation")

        if not confirmation:
            return apology("Must confirm password", 400)
        elif password != confirmation:
            return apology("Password does not match", 400)

        hash = generate_password_hash(password)
    # Can do an if statement to check if username is taken too
        try:
            db.execute("insert into users (username, hash) values (?, ?)", username, hash)
        except:
            return apology("Username is taken", 400) #400 is bad req, 403 is forbidden

        return redirect("/")
    else:
        return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 400)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 400)

        # Query database for username
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
            return apology("invalid username and/or password", 400)

        # Remember which user has logged in
        session["user_id"] = rows[0]["user_id"]
        session.permanent = False

        # Redirect user to home page
        return redirect("/home")

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

@app.route("/home")
@login_required
def home():
    return render_template("home.html")

@app.route("/mydecks")
@login_required
def mydecks():
    decks = db.execute("SELECT DISTINCT category FROM cards WHERE user_id = ?", session["user_id"])

    return render_template("mydecks.html", decks=decks)

@app.route("/addtoexisting")
@login_required
def addtoexisting():
    decks = db.execute("select distinct category from cards where user_id = ?", session["user_id"])
    return render_template("addtoexisting.html", decks=decks)

@app.route("/inputdata", methods=["GET", "POST"])
@login_required
def input_data():
    if request.method == "POST":
        deck_name = request.form.get("deck_name")
        session["selected_deck"] = deck_name
        return redirect(url_for("input_data"))

    deck_name = session["selected_deck"] or request.args.get("deck_name")
    return render_template("inputdata.html", deck_name=deck_name)

@app.route("/addtodeck", methods=["POST"])
@login_required
def add_to_deck():
    user_id = session["user_id"]
    deck_name = request.form.get("deck_name")
    csv_text = request.form.get("csv_text")
    if not csv_text:
        return apology("Must upload a CSV file", 400)

    stream = io.StringIO(csv_text.strip())
    reader = csv.DictReader(stream)

    for row in reader:
        row = {
            (k.strip().lower() if k else "ugly"): safe_strip(v)
            for k, v in row.items()
        }
        db.execute("""
            INSERT INTO cards (user_id, word, kana, romaji, meaning, example_sentence, category)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, user_id,
            row.get("word"),
            row.get("kana"),
            row.get("romaji"),
            row.get("meaning"),
            row.get("example_sentence"),
            deck_name
        )
    flash("Successfully uploaded")
    return redirect("/home")


@app.route("/newdeck", methods=["GET", "POST"])
@login_required
def newdeck():
    if request.method == "POST":
        user_id = session["user_id"]
        deck_name = request.form.get("deck_name")
        csv_text = request.form.get("csv_text")
#converts the uploaded file into a format Python can read like a normal text file.
        if not csv_text:
            return apology("Must upload a CSV file", 400)

        stream = io.StringIO(csv_text.strip())
        reader = csv.DictReader(stream)

        for row in reader:
            row = {
                (k.strip().lower() if k else "u"): safe_strip(v)
                for k, v in row.items()
            }
            print(row)
            if 'number' in row:
                row.pop('number')
            print(row)
            db.execute("""
                INSERT INTO cards (user_id, word, kana, romaji, meaning, example_sentence, category)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, user_id,
                 row.get("word"),
                 row.get("kana"),
                 row.get("romaji"),
                 row.get("meaning"),
                 row.get("example_sentence"),
                 deck_name
            )

        return redirect("/mydecks")
    return render_template("newdeck.html")


@app.route("/deck")
@login_required
def deck():
    deck_name = request.args.get("deck_name")
    card_id = request.args.get("card_id")  # get card_id if passed

    if not deck_name:
        return "Deck name is missing!", 400

    if "round_count" not in session:
        session["round_count"] = 0
    round_count = session.get("round_count")

    # Reset review scores and round count only if starting fresh (no card_id)
    if not card_id:
        db.execute("UPDATE cards SET review_score = 0 WHERE user_id = ? AND category = ?", session["user_id"], deck_name)
        session["round_count"] = 0

    if card_id:
        cards = db.execute("""
            SELECT * FROM cards
            WHERE user_id = ? AND category = ? AND id >= ?
            ORDER BY id ASC
        """, session["user_id"], deck_name, card_id)
    else:
        cards = db.execute("""
            SELECT * FROM cards
            WHERE user_id = ? AND category = ?
            ORDER BY id ASC
        """, session["user_id"], deck_name)

    return render_template("deck.html", deck_name=deck_name, cards=cards, round_count=round_count)


@app.route("/continuereviewing")
@login_required
def continue_reviewing():
    deck_name = request.args.get("deck_name")
    cards = db.execute(
        "SELECT * FROM cards WHERE user_id = ? AND category = ? AND review_score <= 0",
        session["user_id"], deck_name
    )
    completed = len(cards) == 0

    return render_template(
        "deck.html",
        cards=cards,
        deck_name=deck_name,
        completed=completed
    )

@app.route("/updatescore", methods=["POST"])
@login_required
def update_score():
    card_id = request.form.get("card_id")
    delta = int(request.form.get("score"))
    db.execute("UPDATE cards SET review_score = review_score + ? WHERE id = ?", delta, card_id)
    new_score = db.execute("SELECT review_score FROM cards WHERE id = ?", card_id)[0]["review_score"]

    return jsonify({"new_score": new_score})

@app.route("/increment_round", methods=["POST"])
@login_required
def increment_round():
    if "round_count" not in session:
        session["round_count"] = 1
    else:
        session["round_count"] += 1
    return jsonify(round_count=session["round_count"])

@app.route("/cryingmiko")
@login_required
def crying_miko():
    card_id = request.args.get("card_id")
    if not card_id:
        return "Card ID is missing!", 400

    # Query the deck_name (category) from cards where id = card_id
    result = db.execute("SELECT category FROM cards WHERE id = ?", card_id)

    if not result:
        return "Card not found!", 404

    deck_name = result[0]["category"]

    return render_template("cryingmiko.html", card_id=card_id, deck_name=deck_name)
