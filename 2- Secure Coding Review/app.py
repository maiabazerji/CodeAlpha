import os
import sqlite3

from dotenv import load_dotenv
from flask import Flask, g, jsonify, render_template, request
from werkzeug.security import check_password_hash
from werkzeug.utils import secure_filename

load_dotenv()  # Load environment variables

app = Flask(__name__)
# app.config['SECRET_KEY'] = os.urandom(24)
# app.config['SESSION_COOKIE_SECURE'] = True
# app.config['REMEMBER_COOKIE_SECURE'] = True
# app.config['SESSION_COOKIE_HTTPONLY'] = True
# app.config['REMEMBER_COOKIE_HTTPONLY'] = True
# app.config['SESSION_PROTECTION'] = 'strong'


# Load configuration from environment variables
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")
app.config["DATABASE"] = os.getenv("DATABASE_URL", "users.db")


def get_db():
    if "db" not in g:
        print("Database path:", app.config["DATABASE"])  # Add this line to debug
        g.db = sqlite3.connect(app.config["DATABASE"])
    return g.db


@app.teardown_appcontext
def close_db(exception):
    db = g.pop("db", None)
    if db is not None:
        db.close()


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Basic input validation
        if not username or not password:
            return jsonify({"message": "Username and password are required"}), 400

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user and check_password_hash(user["password"], password):
            return jsonify({"message": "Login successful"})
        else:
            return jsonify({"message": "Login failed"}), 401
    return render_template("login.html")


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in {
        "txt",
        "pdf",
        "png",
        "jpg",
        "jpeg",
        "gif",
    }


@app.route("/upload", methods=["POST"])
def upload_file():
    if "file" not in request.files:
        return jsonify({"message": "No file part"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"message": "No selected file"}), 400
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join("uploads", filename))
        return jsonify({"message": "File uploaded successfully", "filename": filename})
    else:
        return jsonify({"message": "Invalid file type"}), 400


if __name__ == "__main__":
    app.run(debug=True)
