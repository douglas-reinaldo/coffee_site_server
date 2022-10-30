from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)

app.config['SECRET_KEY'] = 'eusouachave123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///table.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(300))
    name = db.Column(db.String(1000))

# Line below only required once, when creating DB.
@app.before_first_request
def create_tables():
    db.create_all()


@app.route('/')
def home():
    cafes = list(db.session.query(Cafe))
    return render_template("index.html", logged_in=current_user.is_authenticated, cafes=cafes)


@app.route('/register', methods=["GET", "POST"])
def register():
    if request.method == "POST":

        if User.query.filter_by(email=request.form.get('email')).first():
            # Usuário já existe
            flash("Email já cadastrado, Logue invez! ")
            return redirect(url_for('login'))

        hash_and_salted_password = generate_password_hash(
            request.form.get('password'),
            method='pbkdf2:sha256',
            salt_length=8
        )
        db.create_all()
        new_user = User(
            email=request.form.get('email'),
            password=hash_and_salted_password,
            name=request.form.get('name')
        )

        db.session.add(new_user)
        db.session.commit()

        login_user(new_user)

        return redirect(url_for("secrets"))

    return render_template("register.html", logged_in=current_user.is_authenticated)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == "POST":
        email = request.form.get('email')
        password = request.form.get('password')

        # Encontrar usuario por email
        user = User.query.filter_by(email=email).first()

        # Email errado/inexistente
        if not user:
            flash("Este email não existe. Por favor, tente novamente! ")
            return redirect(url_for('login'))

        # Senha errada
        elif not check_password_hash(user.password, password):
            flash("Senha Incorreta. Por favor, tente novamente! ")
            return redirect(url_for('login'))

        else:
            login_user(user)
            return redirect(url_for('secrets'))
    return render_template("login.html", logged_in=current_user.is_authenticated)


@app.route('/secrets')
@login_required
def secrets():
    print(current_user.name)
    return render_template("secrets.html", name=current_user.name, logged_in=True)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))


@app.route('/download')
@login_required
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")


# ---------------------------------------------------------------------------
##Cafe TABLE Configuration
class Cafe(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), unique=True, nullable=False)
    location = db.Column(db.String(250), nullable=False)
    seats = db.Column(db.String(250), nullable=False)
    coffee_price = db.Column(db.String(250), nullable=True)



## HTTP POST - Create Record
@login_required
@app.route("/add", methods=["GET", "POST"])
def add():
    if request.method == "POST":
        db.create_all()
        new_cafe = Cafe(
            name=request.form.get("name"),
            location=request.form.get("location"),
            seats=request.form.get("seats"),
            coffee_price=request.form.get("coffee_price")
        )
        db.session.add(new_cafe)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('add.html')


@login_required
@app.route('/profile')
def profile():
    return render_template('profile.html', logged_in=current_user.is_authenticated, user=current_user)



if __name__ == "__main__":
    app.run(debug=True)
