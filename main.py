from flask import Flask, render_template, url_for, redirect, request, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
app.app_context().push()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(name):
    return User.query.get(name)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))


# db.create_all()

@app.route('/')
def home():
    return render_template("index.html")


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if User.query.filter_by(email=request.form.get('email')).first():
            flash("You've already signed up with that email.  Log in instead.")
            return redirect(url_for("login"))
        else:
            hash_and_salted_password = generate_password_hash(
                request.form.get('password'),
                method='pbkdf2:sha256',
                salt_length=8
            )
            new_user = User(
                email=request.form.get('email'),
                name=request.form.get('name'),
                password=hash_and_salted_password
            )
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for("secrets"))
    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = User.query.filter_by(email=request.form.get('email')).first()
        if user is None:
            flash("That email does not exist.  Please try again.")
        elif check_password_hash(user.password, request.form.get('password')):
            login_user(user)
            return redirect(url_for('secrets'))
        else:
            flash("Password incorrect.  Please try again.")
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets', methods=["GET", "POST"])
@login_required
def secrets():
    name = current_user.name
    return render_template("secrets.html", name=name, logged_in=current_user.is_authenticated)


@app.route('/download')
@login_required
def download():
    return send_from_directory(directory='static/files', path="cheat_sheet.pdf", as_attachment=False)


@app.route('/logout', methods=["GET", "POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
