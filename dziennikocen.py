#LIBRARY FOR FLASK
from flask import Flask, request,render_template,url_for,session
from flask.helpers import redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_manager, login_user,LoginManager, login_required,logout_user, current_user
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import StringField, SubmitField,PasswordField,SelectField,IntegerField
from wtforms.validators import InputRequired, Length, ValidationError,DataRequired
from flask_bcrypt import Bcrypt
#LIBRARY FOR SQL
from sqlalchemy import create_engine, and_,select
import psycopg2

#CONFIG APP & DB
try:
   conn = psycopg2.connect(host="localhost",
                            user="postgres",
                            password="michal12",
                            database="dziennikocen")
except:
    print("Show error")
mycursor =conn.cursor()
engine = create_engine('postgresql+psycopg2://postgres:michal12@localhost/dziennikocen')
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:michal12@localhost/dziennikocen'
app.config['SECRET_KEY'] ='sekretnyklucz'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)
csrf.init_app(app)
#LOGIN MANAGENING
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader 
def load_user(user_id):
    return Uzytkownicy.query.get(int(user_id))

#CLASSES
class Uzytkownicy(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)

class Studenci(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    nr_albumu = db.Column(db.String(4),nullable=False,unique=True)
    imie = db.Column(db.String(255),nullable=False)
    nazwisko = db.Column(db.String(255),nullable=False)
    email = db.Column(db.String(255),nullable=False)
    nrtelefonu = db.Column(db.String(255),nullable=False)

class Prowadzacy(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    imie = db.Column(db.String(255),nullable=False)
    nazwisko = db.Column(db.String(255),nullable=False)
    email = db.Column(db.String(255),nullable=False)
    nrtelefonu = db.Column(db.String(255),nullable=False)

class Przedmioty(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    nazwa = db.Column(db.String(255),nullable=False)
    prowadzacy = db.Column(db.String(255),nullable=False)

class Projekty(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    nazwa = db.Column(db.String(255),nullable=False)
    promotor = db.Column(db.String(255),nullable=False)
    grupa = db.Column(db.String(255),nullable=False)
    data = db.Column(db.Date,nullable=False)
    student_id = db.Column(db.String(4))

class Oceny(db.Model):
    id = db.Column(db.Integer,primary_key=True)
    nazwa_przedmiotu = db.Column(db.String(255),nullable=False)
    ocena_przedmiot = db.Column(db.Integer,nullable=False)
    nazwa_projektu = db.Column(db.String(255),nullable=False)
    ocena_projekt = db.Column(db.Integer,nullable=False)
    egzamin = db.Column(db.String(255),nullable=False)
    ocena_egzamin = db.Column(db.Integer,nullable=False)

class RegisterForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Nr albumu"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Haslo"})
    submit = SubmitField("Register")
   
    def validate_username(self,username):
        existing_user_username = Uzytkownicy.query.filter_by(username=username.data).first()
        if existing_user_username:
            raise ValidationError("Nazwa uzytkownika juz istnieje. Proszę wybrać inna nazwe.")
    
class LoginForm(FlaskForm):
    username = StringField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Nr albumu"})
    password = PasswordField(validators=[InputRequired(),Length(min=4,max=20)],render_kw={"placeholder":"Haslo"})
    submit = SubmitField("Login")

class PrzypiszProjektForm(FlaskForm):
    projekty = SelectField('Projekty', choices=[], validators=[DataRequired()])
    student_id = StringField('student_id', validators=[InputRequired()])
    submit = SubmitField('Przypisz')


#PAGES CONFIG
@app.route('/')
def index():
    return render_template('home.html')

@app.route('/user/oceny')
def oceny():
    mycursor.execute(Oceny.select())
    data = mycursor.fetchall()
    return render_template('template.html', data=data)

@app.route('/user/dane',methods=['GET','POST'])
@login_required
def dane():
    if 'username' in session:
        user = session['username']
        mycursor.execute(
            "SELECT s.nr_albumu, s.imie, s.nazwisko, s.email, s.nrtelefonu "
            "FROM studenci s "
            "JOIN uzytkownicy u ON s.id = u.id "
            "WHERE u.username = %s",
            (user,)
        )
        dane = mycursor.fetchall()
        return render_template('dane.html', data=dane)
    else:
        return redirect(url_for('login'))

@app.route('/user/tematy', methods=['GET','POST'])
@login_required
def tematy():
    user = session['username']
    form1 = LoginForm()
    form = PrzypiszProjektForm()
    mycursor.execute('SELECT nazwa, promotor FROM Projekty WHERE student_id is NULL')
    tematy = mycursor.fetchall()
    form.projekty.choices = [(t[0], t[1]) for t in tematy]
    
    if form.validate_on_submit():
        projekt_nazwa = form.projekty.data
        student_id = user
        mycursor.execute(
            "UPDATE Projekty SET student_id = %s WHERE nazwa = %s",
            (student_id, projekt_nazwa))
        conn.commit()
        return redirect(url_for('tematy'))
    return render_template('tematy.html', data=tematy, form=form,form1=form1)


        

@app.route('/login', methods=['GET','POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit(): 
        user = Uzytkownicy.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password,form.password.data):
                login_user(user) 
                session['username'] = form.username.data
                return redirect(url_for('dashboard'))
    return render_template('login.html',form=form)

@app.route('/user',methods=['GET','POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout',methods=['GET','POST'])
@login_required 
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        new_user = Uzytkownicy(username=form.username.data,password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html',form=form)


if __name__ == "__main__":
    app.run(debug=True)