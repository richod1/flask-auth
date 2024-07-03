from flask import Flask,render_template,redirect,url_for,request,flash
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager,UserMixin,login_user,current_user,logout_user,login_required

app=Flask(__name__)
app.config['SECRET_KEY']='6c31ee160ce76ab3f3bb07a647ed2253d15dc06a3c57c1cc27d4cd43ce849665'
app.config['SQLALCHEMY_DATABASE_URI']='sqlite:///site.db'
db=SQLAlchemy(app)
bcrypt=Bcrypt(app)
login_manager=LoginManager(app)
login_manager.login_view='login'
login_manager.login_message_category='info'


# db models
class User(db.Model,UserMixin):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(20),unique=True,nullable=False)
    email=db.Column(db.String(20),unique=True,nullable=False)
    password=db.Column(db.String(60),nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/")
@app.route("/home")
def home():
    return render_template('home.html')


@app.route('/register',methods=['GET','POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method=='POST':

        username=request.form.get('username')
        email=request.form.get('email')
        password=request.form.get('password')
        hashed_password=bcrypt.generate_password_hash(password).decode('utf-8')
        # for confirmation for hashed password
        check_for_password_hashed=bcrypt.check_password_hash(hashed_password)
        if(check_for_password_hashed==True):
            print('password has been hashed successfully')
        user=User(username=username,email=email,password=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created successfully','success')
        return redirect(url_for('login'))
    return render_template('register')
    




if __name__=='__main__':
    app.run(debug=True)

