# surya ver
import smtplib
import socket
import time
import csv
import authlib
from password_strength import PasswordPolicy
from password_strength import PasswordStats
import oauthlib.oauth2.rfc6749.errors
import twilio.base.exceptions
from flask import Flask, render_template, flash, request, redirect,url_for, session,g
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import UserMixin, login_user,LoginManager,login_required,logout_user, current_user
import string
import random
from twilio.rest import Client
from webforms import *
from flask_ckeditor import CKEditor
from werkzeug.utils import secure_filename
import uuid as uuid
import os
from re import search
from passlib.hash import argon2
import pyperclip
from random import randint
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadTimeSignature, TimedSerializer,TimestampSigner
from flask_mail import Mail, Message
from authlib.integrations.flask_client import OAuth
import rsa
import os
import pathlib
import requests
from requests import ReadTimeout, Timeout
from flask import Flask, session, abort, redirect, request
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
import hashlib
import math
from Crypto.Cipher import AES
from flask_wtf.csrf import CSRFProtect, CSRFError
from datetime import date

#create flask instance
app= Flask(__name__)
ckeditor= CKEditor(app)
app.config['MAIL_SERVER']='smtp-mail.outlook.com.'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'FlaskerBlog@outlook.com'
app.config['MAIL_PASSWORD'] = 'Benboy121203'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_MAX_EMAILS'] = 1
mail = Mail(app)
s = URLSafeTimedSerializer('secret_key_val')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = "9#35I0(6(k^QC()"
app.config['WTF_CSRF_SECRET_KEY'] = b'(p54*!W$9q#3r2$'
UPLOAD_FOLDER = 'static/images/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
#init db
db= SQLAlchemy(app)
migrate = Migrate(app, db)
oauth = OAuth(app)
CSRFProtect(app)

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  #this is to set our environment to https because OAuth 2.0 only supports https environments
GOOGLE_CLIENT_ID = "655341561563-2105665npodji9vb2btm0i1vi8d4fb62.apps.googleusercontent.com"  #enter your client id you got from Google console
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")  #set the path to where the .json file you got Google console is
flow = Flow.from_client_secrets_file(  #Flow is OAuth 2.0 a class that stores all the information on how we want to authorize our users
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],  #here we are specifing what do we get after the authorization
    redirect_uri="http://127.0.0.1:5000/callback"  #and the redirect URI is the point where the user will end up after the authorization
)

app.config['GITHUB_CLIENT_ID'] = "605874ff75eb3ffa4ece"
app.config['GITHUB_CLIENT_SECRET'] = "e883d20d8ecf41bae277b349976528cac9b8bf26"
github = oauth.register (
    name = 'github',
    client_id = app.config["GITHUB_CLIENT_ID"],
    client_secret = app.config["GITHUB_CLIENT_SECRET"],
    access_token_url = 'https://github.com/login/oauth/access_token',
    access_token_params = None,
    authorize_url = 'https://github.com/login/oauth/authorize',
    authorize_params = None,
	api_base_url = 'https://api.github.com/',
    client_kwargs = {'scope': 'user:email'},
)

account_sit = "ACcc421eacaf12e7fac7845b6fa742b904"
auth_token = "0b11d4860a7c7e78d3e4cccce17ec7a2"
client = Client(account_sit,auth_token)

#flask login config
login_manager= LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

IV_SIZE = 16    # 128 bit, fixed for the AES algorithm
KEY_SIZE = 32   # 256 bit meaning AES-256, can also be 128 or 192 bits
SALT_SIZE = 16  # This size is arbitrary
password = b'1W$&G@(!%%#)^(q2!@%)5#t05Q#%$#@@c()#x(8#%(t021!^2730$&0!@I)@w&(((#@#(XnL3^!I&%ZKi!21C@@0!%yc&^66'

# Password Policy Config
policy = PasswordPolicy.from_names(
    length=8,  # min length: 8
    uppercase=2,  # need min. 2 uppercase letters
    numbers=2,  # need min. 2 digits
    special=2,  # need min. 2 special characters
    nonletters=2,  # need min. 2 non-letter characters (digits, specials, anything)
)

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LfwMHIhAAAAAF2Qw4NVU_p-R_2NXNCT5Dmz-NzR'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LfwMHIhAAAAAF1hAAWeQTU9q7sL74_sm0RCXTVW'


def generate_salt():
    return os.urandom(SALT_SIZE)

def encrypt_data(salt_value, data):
    data = data.encode()
    derived = hashlib.pbkdf2_hmac('sha256', password, salt_value, 100000, dklen=IV_SIZE + KEY_SIZE)
    iv = derived[0:IV_SIZE]
    key = derived[IV_SIZE:]

    return salt_value + AES.new(key, AES.MODE_CFB, iv).encrypt(data)

def decrypt_data(encrypted):
    salt = encrypted[0:SALT_SIZE]
    derived = hashlib.pbkdf2_hmac('sha256', password, salt, 100000, dklen=IV_SIZE + KEY_SIZE)
    iv = derived[0:IV_SIZE]
    key = derived[IV_SIZE:]
    return AES.new(key, AES.MODE_CFB, iv).decrypt(encrypted[SALT_SIZE:]).decode()

@login_manager.user_loader
def load_user(user_id):
    try:
        user= Users.query.get(user_id)
        return user
    except ValueError:
        flash('There Was A Problem Loading Your Account.','error')
        return redirect(url_for('index'))

@app.context_processor
def base():
    try:
        form=SearchForm()
        return dict(form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/search', methods=["POST"])
def search():
    try:
        form= SearchForm()
        posts = Posts.query
        if form.validate_on_submit():
            #get data from submitted form
            post.searched =form.searched.data
            #query db
            posts = posts.filter(Posts.content.like('%' + post.searched + '%'))
            posts = posts.order_by(Posts.title).all()
            return render_template('search.html',
                            form=form,
                            searched=post.searched,
                            posts=posts)
        else:
            flash('Please search for a blog post.')
            return redirect(url_for('posts'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/')
def index():
    try:
        return render_template('index.html')
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#ADD USER FUNCTIONS (REGULAR)
@app.route('/user/add',methods=["GET","POST"])
def add_user():
    try:
        name =None
        form= UserForm()
        if form.validate_on_submit():
            passwords= []
            with open('common_password.csv', 'r') as csv_file:
                csv_reader = csv.reader(csv_file)
                for line in csv_reader:
                    passwords.append(line[0])
            user = Users.query.filter_by(email=form.email.data).first()
            user_username_in_db = Users.query.filter_by(username= form.username.data).first()

            if user is None:
                user_password = form.password_hash.data
                # Checking stats for form.password_hash.data
                stats = PasswordStats(user_password)
                checkpolicy = policy.test(user_password)
                #Use the statements to check if the Password requirements are met or not
                # print(checkpolicy)
                # print(stats)
                # print(stats.strength())
                #hashing the user entered password
                hashed_pw= argon2.hash(user_password)

                if user_username_in_db is not None:
                    flash('Username exists. Try Again', 'warning')
                    return redirect(url_for('add_user'))

                if ( user_password.lower() in form.username.data.lower() ) or ( user_password.lower() in form.username.data[::-1].lower() ):
                    flash('Password cannot contain username. Please Try Again', 'warning')
                    return redirect(url_for('add_user'))

                if form.password_hash.data in passwords:
                    flash('Your Password Has Been Identified as a Common Password. For Your Safety, This Password Cannot Be Used. Please Choose A Stronger Password Or Use Our Password Generator', 'warning')
                    return redirect(url_for('add_user'))

                if form.password_hash.data in form.email.data:
                    flash('Password Contains Email. Please Choose A Password That Does Not Contain Any Personal Identifying Information Such As Name, Username, Email Etc. '
                          'Please Click On Our Password Generator For A Strong Password', 'warning')
                    return redirect(url_for('add_user'))

                if stats.strength() < 0.66:
                    strength = stats.strength()
                    if stats.strength() <0.33:
                        strength = "Very Weak"
                    elif stats.strength() <0.5:
                        strength = "Weak"
                    else:
                        strength = "Medium"
                    flash(f'Your password is considered as a {strength} Level Password. You may consider using our password generator','warning')
                    return redirect(url_for('add_user'))


                elif stats.strength() > 0.66 and policy.test(user_password) != []:
                    unfufilled_requirements_list = checkpolicy
                    flash('You have failed to meet the following requrements','warning')
                    for i in checkpolicy:
                        flash(f'{i}','warning')

                elif stats.strength()> 0.66 and policy.test(user_password) == []:
                    #This is the success elif block
                    try:
                        email = form.email.data
                        token = s.dumps(email, salt='N0#!7^z@4Bq43!&',)

                        msg = Message(email, sender='FlaskerBlog@outlook.com', recipients=[email])
                        link = url_for('add_user_email_verify', token=token, _external=True)
                    except TimeoutError:
                        flash('Request is taking too long too load. Please try again later', 'error')
                        return redirect(url_for('add_user'))
                    try:
                        msg.body = f'Thank you for using FlaskerBlog. The link to access your account is: {link}. If you did not create an account, we would advise you to not to share any OTP you may receive.'
                        mail.connect()
                        mail.send(msg)
                        # encrypts data before storing into db (encrypts name for now)

                        session["name"] = form.name.data
                        session["username"] = form.username.data
                        session["email"] = email
                        session["gender"] = form.gender.data
                        session["dob"] = form.dob.data
                        session["address"] = form.address.data
                        session["password_hash"] = hashed_pw
                        session["counter"] = form.counter.data
                        session["login_count"] = form.login_count.data

                        flash('An email has been sent to your email address. Please click on the link to verify your account.','success')
                        return redirect(url_for('add_user'))
                    except socket.gaierror:
                        flash('No Connection Detected. Please Try Again', 'error')
                        return redirect(url_for('index'))
                    except smtplib.SMTPServerDisconnected:
                        flash('A Server Connection Has Occured. Please Try Again Later.','error')
                        return redirect(url_for('index'))
                    except OSError:
                        flash('A Network Connection Has Occured. Please Try Again Later.','error')
                        return redirect(url_for('index'))
            elif user is not None:
                flash('Email Already Exists! Please Login If You Have An Account', 'warning')
                return redirect(url_for('login'))
            name= form.name.data
            form.name.data= ''
            form.username.data= ''
            form.email.data= ''
            form.dob.data= ''
            form.password_hash.data = ''
        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user.html",
                               form=form,
                               name=name,
                               our_users=our_users
                               )
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/random_pass',methods=["GET","POST"])
def random_pass():
    try:
        password= None
        form =RandomPassForm()
        #validate form
        if form.validate_on_submit():
            ## characters to generate password from
            alphabets = list(string.ascii_letters)
            lowercase = list(string.ascii_lowercase)
            uppercase = list(string.ascii_uppercase)
            digits = list(string.digits)
            special_characters = list("!@#$%^&*()")
            characters = list(string.ascii_lowercase+ string.ascii_uppercase + string.digits + "!@#$%^&*()")

            length = 18
            ## length of password from the user
            ## number of character types
            alphabets_count = 8
            digits_count = 6
            special_characters_count = 4

            characters_count = alphabets_count + digits_count + special_characters_count

            ## check the total length with characters sum count
            ## print not valid if the sum is greater than length
            if characters_count > length:
                return
            ## initializing the password
            password = []
            ## picking random alphabets
            for i in range(alphabets_count):
                password.append(random.choice(alphabets))
            ## picking random digits
            for i in range(digits_count):
                password.append(random.choice(digits))
            ## picking random alphabets
            for i in range(special_characters_count):
                password.append(random.choice(special_characters))
            ## if the total characters count is less than the password length
            ## add random characters to make it equal to the length
            if characters_count < length:
                random.shuffle(characters)
                for i in range(length - characters_count):
                    password.append(random.choice(characters))
            ## shuffling the resultant password
            random.shuffle(password)
            ## converting the list to string
            form.random_password.data=   ("".join(password))
            pyperclip.copy(form.random_password.data)
            flash("Random Password Generated Successfully and Copied To Clipboard.")
        return render_template('random_pass.html',
                               password=password,
                               form=form)

    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/email_confirm/<token>', methods=["GET","POST"])
def add_user_email_verify(token):
    try:
        if request.method == "GET":
            try:
                name = session["name"]
                counter = session["counter"]
                login_count = session["login_count"]
                username = session["username"]
                email = session["email"]
                email = s.loads(token,salt='N0#!7^z@4Bq43!&', max_age=300) #max_age in sec give drf of 300 sec (5 min) CHANGE TO 50 FOR DEMO
                dob = session["dob"]
                address = session["address"]
                gender = session["gender"]
                password_hash = session["password_hash"]
                flash('Email Has been Verified. Thank You', 'success')
                return redirect(url_for('add_user_telno_verify'))
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('add_user'))
            except:
                flash('Adding Account Process Done Incorrectly. Please Do Not Tamper With The URL','error')
                return redirect(url_for('index'))
        else:
            flash('An Error Has Occured When Verifying Email. Please Try Again Later', 'error')
            return redirect(url_for('add_user'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/telno_verify', methods=["GET","POST"])
def add_user_telno_verify():
    try:
        try:
            counter = session["counter"]
            login_count = session["login_count"]
            name = session["name"]
            username = session["username"]
            email = session["email"]
            dob = session["dob"]
            gender = session["gender"]
            password_hash = session["password_hash"]
        except:
            flash('Adding Account Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))
        form= PhoneVerifyForm()
        if form.validate_on_submit():
            user_tel = Users.query.filter_by(tel_phone = form.countryCode.data+form.telnoverify.data).first()
            if user_tel is None: #el num not in db
                #sms part
                countryCode = form.countryCode.data
                telnoverify = form.telnoverify.data
                tel_phone = countryCode+telnoverify
                otp = random.randint(100000,999999)
                client.messages.create(
                body = f"You OTP is {otp}",
                    from_= "+14242030414", #Change the Phone number. MUST include the '+' at the front
                    to= countryCode+telnoverify
                )
                otp = encrypt_data(generate_salt(), str(otp))
                session["otp"] = otp
                session["tel_phone"] = tel_phone
                flash('Please enter the OTP that was recently sent','warning')
                return redirect(url_for('add_user_otp_verify'))

            else:
                flash('Tel Phone Number Already Registerd. Please Try Again','error')
                return redirect(url_for('add_user_telno_verify'))

        return render_template('add_user_telno_verify.html',
                                   form=form
                               )
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/otp_verify', methods=["GET","POST"])
def add_user_otp_verify():
    try:
        form= OTPVerifyForm()
        try:
            counter = session["counter"]
            login_count = session["login_count"]
            name = session["name"]
            username = session["username"]
            email = session["email"]
            dob = session["dob"]
            gender = session["gender"]
            address = session["address"]
            password_hash = session["password_hash"]
            tel_phone = session["tel_phone"]
            otp = session["otp"]
        except:
            flash('Adding Account Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))
        if otp == None:
            flash('OTP has expired or is Invalid. Please try again. Check your details again carefully.','error')
            return redirect(url_for('add_user_telno_verify'))
        else:
            otp = decrypt_data(otp)
            otp = int(otp)

        if form.validate_on_submit():
            if form.OTP.data == otp:

                session["otp"] = session.pop(otp,None)

                name = encrypt_data(generate_salt(),name)
                email = encrypt_data(generate_salt(), email)


                dob = encrypt_data(generate_salt(),dob)
                address = encrypt_data(generate_salt(),address)

                user = Users(name=name, username=username,email= email, dob= dob, password_hash = password_hash, gender=gender,tel_phone =tel_phone, address = address,user_secure_question_attempt= 3,counter = counter, login_count = login_count)
                db.session.add(user)
                db.session.commit()

                userpass = user.id
                usedpassword = UsedPass(password= password_hash, pass_user_id= userpass)
                db.session.add(usedpassword)
                db.session.commit()

                db.session.add(user)
                db.session.commit()
                userlog = UsersLog(login_counter = login_count, userid = user.id)
                db.session.add(userlog)
                db.session.commit()

                client.messages.create(
                body = f"You Have Successfully Registered With FlaskBlog. As part Of Our Efforts To Step Up Our Security Measures To Protect Your Account,"
                       f" We Will Send You An SMS Everytime Your Account Has Been Logged Into. Wish You A Good Day Ahead."
                       f" If you did not create an account with us, we would encourage you to delete your account. Check your emails. If you see a verification email from us,"
                       f" that was the account that was used to create an account.-FlaskBlog",
                    from_= "+14242030414",
                    to= tel_phone
                )
                login_user(user,remember=False)
                flash('In the future, you may need to change your account details. As such, we would require you to have at least 1 security question as a 2FA step.','info')
                return redirect(url_for('add_security_question'))
            else:
                session["otp"] = session.pop(otp,None)
                flash('You Have Entered The Wrong OTP Password. Please verify your phone number.','error')
                return redirect(url_for('add_user_telno_verify'))

        else:
            return render_template('add_user_otp_verify.html',
                                   form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/expire_otp', methods=["GET","POST"])
def expire_otp_add_user():
    try:
        otp =session["otp"]
        session["otp"] = session.pop(otp,None)

        return redirect(url_for('add_user_otp_verify'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/add_security_question',methods=["GET","POST"])
@login_required
def add_security_question():
    try:
        form = SecurityQuestion()
        id = current_user.id
        if form.validate_on_submit():
            user_security_question = form.security_question.data
            user_security_answer = form.security_answer.data
            user = Users.query.filter_by(id=id).first() #Filers using the users id
            if user:
                user_id = user.id
                user_security = UsersSecurityQuestion.query.filter_by(user_id = user_id).all()
                if not user_security: #User has no question in db
                    user_security = UsersSecurityQuestion(security_question_id= user_security_question,security_answer=encrypt_data(generate_salt(),user_security_answer),user_id = user_id)
                    db.session.add(user_security)
                    db.session.commit()
                    flash('Successfully added in your first 2FA security question.','success')
                    return redirect(url_for('index'))
                elif user_security: #User has a question in db

                    user_security_questions_list =[]
                    for i in user_security:  #loops through each pass_user_id
                        answered_questions= i.security_question_id
                        user_security_questions_list.append(answered_questions)

                    for i in range(len(user_security_questions_list)):
                        if user_security_question == user_security_questions_list[i]:
                            flash('You have an answer for this question. Please choose a question that you have not answered.','warning')
                            return redirect(url_for('add_security_question'))
                        else:
                            i +=1
                            if i == len(user_security_questions_list):
                                user_security = UsersSecurityQuestion(security_question_id= user_security_question,
                                                                      security_answer=encrypt_data(generate_salt(),user_security_answer),user_id = user_id)
                                db.session.add(user_security)
                                db.session.commit()
                                flash('New security question 2FA successfully added','success')
                                return redirect(url_for('index'))

            else:
                flash('In order to create security question 2FA, you would need to have an account','warning')
                return redirect(url_for('add_user'))
        else:
            return render_template('add_security_question.html',form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
#END OF ADD USER FUNCTIONS (REGULAR)

#----------------------------------------------------------------------------------------------------------------------------------

#ADD USER FUNCTIONS (GOOGLE)

@app.route("/google_login")  #the page where the user can login
def google_login():
    try:
        authorization_url, state = flow.authorization_url()  #asking the flow class for the authorization (login) url
        session["state"] = state
        return redirect(authorization_url)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route("/callback")  #this is the page that will handle the callback process meaning process after the authorization
def callback():
    try:
        try:
            flow.fetch_token(authorization_response=request.url)
            if not session["state"] == request.args["state"]:
                abort(500)  #state does not match!
            credentials = flow.credentials
            request_session = requests.session()
            cached_session = cachecontrol.CacheControl(request_session)
            token_request = google.auth.transport.requests.Request(session=cached_session)
            id_info = id_token.verify_oauth2_token(
                id_token=credentials._id_token,
                request=token_request,
                audience=GOOGLE_CLIENT_ID,
                clock_skew_in_seconds= 10 #10 seconds Validity period
            )
            view = id_info
            resp = view
            session['id'] = view.get('sub')
            google_id = session['id']
            session['name'] = view.get('name')
            session['email'] = view.get('email')
            user = Users.query.filter_by(google_id=google_id).first()
            flash('Google Sign In Successful.','success')
            if user is not None:
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('You will still need to fill in the details below to use our services','warning')
                return redirect(url_for('add_user_google'))
        except oauthlib.oauth2.rfc6749.errors.InvalidGrantError:
            flash('Authentication Token Has Expired', 'error')
            return redirect(url_for('index'))
        except oauthlib.oauth2.rfc6749.errors.MissingCodeError:
            flash('Authentication Token is incorrect. Please try again', 'error')
            return redirect(url_for('login'))
        except ValueError:
            flash('Authentication Token and computer time are mismatched. This can be fixed by changing the Timezone in your computer settings.','error')
            flash('If the problem persists, try restarting your device. We apologise for the inconvience caused. Try Github Login as an alternative.','error')
            return redirect(url_for('login'))

    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
@app.route('/add_user_google', methods=['GET','POST'])
def add_user_google():
    try:
        form = GoogleLoginForm()
        try:
            google_name = session['name']
            google_id = session["id"]
            google_email = session['email']
        except:
            flash('Adding Account Via Google Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))

        if form.validate_on_submit():

            user = Users.query.filter_by(username= form.username.data).first()
            tel_phone = form.countryCode.data+form.tel_phone.data
            user_tel = Users.query.filter_by(tel_phone=tel_phone).first() #checks to see if this phone num is alrd in db
            if user is None and user_tel is None: #NO Record of ALL Col of this user in the DB
                otp = random.randint(100000,999999)
                client.messages.create(
                    body = f"Welcome user, As you are signing in to our service using google for the first time, we would need to validate your phone number. To validate your phone number, enter the OTP: {otp}. If this was NOT you, please sign in using your Google address/es and check if there are any emails that have an account which you did not create. Delete those accounts immediately. Have a wonderful time using our App. -FlaskerBlog ",
                    from_= "+14242030414",
                    to= tel_phone
                )
                session["otp"] = otp

                session["id"] = google_id
                session['name']= google_name
                session["username"] = form.username.data
                session["dob"] = form.dob.data
                session["address"] = form.address.data
                session["tel_phone"] = tel_phone
                session['email'] = google_email
                return redirect(url_for('otp_verify_google_login'))
            elif user is not None:
                flash('Username Has Been Taken. Please Choose A New Username','warning')
                return redirect(url_for('add_user_google'))
            elif user_tel is not None: #User has a registerd number in DB, has a valid registerd account, sign in to that account
                flash('This account is already registered. Please log in use our services..','info')
                return redirect(url_for('login'))

        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user_google.html",
            form=form,
            our_users=our_users,
            google_name= google_name,
            google_email = google_email
            )
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/otp_verify_google_login',methods=["GET","POST"])
def otp_verify_google_login():
    try:
        try:
            google_id= session["id"]
            name= session['name']
            username = session["username"]
            dob = session["dob"]
            address = session["address"]
            tel_phone = session["tel_phone"]
            email = session['email']
        except:
            flash('Login Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))

        if session["otp"] == None:
            flash('OTP has expired or is Invalid. Please try again. Check your details again carefully.','error')
            return redirect(url_for('add_user_google'))

        otp = session["otp"]
        form = GoogleAddUserOTPVerifyForm()
        if form.validate_on_submit():
            if form.otp.data == session["otp"]:
                session["otp"] = session.pop(otp,None)
                flash('You have successfully logged in using Google. Hope you enjoy using our services','success')
                name = encrypt_data(generate_salt(),name)
                username = username
                dob = encrypt_data(generate_salt(),dob)
                address = encrypt_data(generate_salt(),address)
                email = encrypt_data(generate_salt(),email)
                tel_phone = tel_phone
                google_id = google_id
                google_user = Users(name =name,username=username,dob=dob,address=address,email=email,tel_phone=tel_phone,google_id=google_id)
                db.session.add(google_user)
                db.session.commit()
                login_user(google_user,remember=False)
                return redirect(url_for('dashboard'))
            else:
                session["otp"] = session.pop(otp,None)
                flash('OTP is incorrect. This OTP is now Invalid. Please check your details again carefully','error')
                return redirect(url_for('add_user_google'))

        return render_template('otp_verify_google_login.html',
                               form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
@app.route('/expire_otp_google_login',methods=["GET","POST"])
def expire_otp_google_login():
    try:
        otp =session["otp"]
        session["otp"] = session.pop(otp,None)
        return redirect(url_for('otp_verify_google_login'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#END OF ADD_USER FUNCTIONS (GOOGLE)
#--------------------------------------------------------------------------------------------------
#ADD_USER FUNCTIONS (GITHUB)

# Github login route
@app.route('/login/github')
def github_login():
    try:
        github = oauth.create_client('github')
        redirect_uri = url_for('github_authorize', _external=True)
        return github.authorize_redirect(redirect_uri)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

# Github authorize route
@app.route('/login/github/authorize')
def github_authorize():
    try:
        try:
            github = oauth.create_client('github')
            token = github.authorize_access_token()
            resp = github.get('user').json()
            git_pass = resp.get('node_id')
            git_avatar_url = resp.get('avatar_url')
            git_id = resp.get('id')
            git_username = resp.get('login')
            github_login()
            session["id"]= git_id
            session["login"] = git_username
            session["avatar_url"] = git_avatar_url
            flash('GitHub Sign In Successful.','success')
            user = Users.query.filter_by(git_id=git_id).first()
            if user is not None:
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('You will still need to fill in the details below to use our services','warning')
                return redirect(url_for('add_user_github'))
        except authlib.integrations.flask_client.OAuthError:
            flash('Oauth verification token has expired. Please try again','error')
            return redirect(url_for('login'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/add_user_github', methods=['GET','POST'])
def add_user_github():
    try:
        form = GithubForm()
        try:
            git_username = session['login']
            git_id = session["id"]
        except:
            flash('Adding Account Via Github Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))

        if form.validate_on_submit():
            user = Users.query.filter_by(username= form.username.data).first()
            tel_phone = form.countryCode.data+form.tel_phone.data
            user_tel = Users.query.filter_by(tel_phone=tel_phone).first() #checks to see if this phone num is alrd in db
            if user is None and user_tel is None: #NO Record of ALL Col of this user in the DB
                otp = random.randint(100000,999999)
                client.messages.create(
                    body = f"Welcome user, As you are signing in to our service using Github for the first time, we would need to validate your phone number. To validate your phone number, enter the OTP: {otp}. If this was NOT you, please sign in using your Google address/es and check if there are any emails that have an account which you did not create. Delete those accounts immediately. Have a wonderful time using our App. -FlaskerBlog ",
                    from_= "+14242030414",
                    to= tel_phone
                )
                session["otp"] = otp

                session["id"] = git_id
                session['name']= form.name.data
                session["username"] = form.username.data
                session["dob"] = form.dob.data
                session["address"] = form.address.data
                session["tel_phone"] = tel_phone
                session['email'] = form.email.data
                return redirect(url_for('otp_verify_github_login'))

            elif user is not None or user:
                flash('Username Has Been Taken. Please Choose A New Username','warning')
                return redirect(url_for('add_user_github'))

            elif user_tel is not None: #User has a registerd number in DB, has a valid registerd account, sign in to that account
                flash('This account is already registered. Please log in use our services..','info')
                return redirect(url_for('login'))

        our_users = Users.query.order_by(Users.date_added)
        return render_template("add_user_github.html",
            form=form,
            our_users=our_users,
            git_username=git_username)

    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/otp_verify_github_login',methods=["GET","POST"])
def otp_verify_github_login():
    try:

        try:
            git_id= session["id"]
            name= session['name']
            username = session["username"]
            dob = session["dob"]
            address = session["address"]
            tel_phone = session["tel_phone"]
            email = session['email']
        except:
            flash('Github login Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))

        otp = session["otp"]
        if otp == None:
            flash('OTP has expired or is Invalid. Please try again. Check your details again carefully.','error')
            return redirect(url_for('add_user_github'))

        form = GithubAddUserOTPVerifyForm()
        if form.validate_on_submit():
            if form.otp.data == session["otp"]:
                session["otp"] = session.pop(otp,None)
                flash('You have successfully logged in using Github. Hope you enjoy using our services','success')
                name = encrypt_data(generate_salt(),name)
                username = username
                dob = encrypt_data(generate_salt(),dob)
                address = encrypt_data(generate_salt(),address)
                email = encrypt_data(generate_salt(),email)
                tel_phone = tel_phone
                git_id = git_id
                github_user = Users(name =name,username=username,dob=dob,address=address,email=email,tel_phone=tel_phone,git_id=git_id)
                db.session.add(github_user)
                db.session.commit()
                login_user(github_user,remember=False)
                return redirect(url_for('dashboard'))
            else:
                session["otp"] = session.pop(otp,None)
                flash('OTP is incorrect. This OTP is now Invalid. Please check your details again carefully','error')
                return redirect(url_for('add_user_github'))

        return render_template('otp_verify_github_login.html',
                               form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
@app.route('/expire_otp_github_login',methods=["GET","POST"])
def expire_otp_github_login():
    try:
        otp =session["otp"]
        session["otp"] = session.pop(otp,None)
        return redirect(url_for('otp_verify_github_login'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#END OF ADD_USER FUNCTIONS (GITHUB)
#--------------------------------------------------------------------------------------------------

#LOGIN FUNCTIONS
@app.route('/login',methods=["GET","POST"])
def login():
    try:
        form=LoginForm()
        if form.validate_on_submit():
            username = form.username.data
            #form is submmitted, login process
            user=Users.query.filter_by(username=username).first()
            #descening


            if user: #username in db
                #check hash
                counter = int(user.counter)
                userlog=UsersLog.query.filter_by(userid=user.id).first()
                logger = int(userlog.login_counter)

                login_count = int(user.login_count)
                if counter > 1:
                    if argon2.verify(form.password.data,user.password_hash): #correct username & password
                        email = user.email
                        email = decrypt_data(email)
                        tel_phone = user.tel_phone
                        if form.login_method.data == "Email":
                            try:
                                token = s.dumps(email, salt='N0#!7BOqq43!&')
                                msg = Message(email,sender='FlaskerBlog@outlook.com', recipients=[email])
                                link = url_for('dashboard_login',token= token,_external=True) #Add token
                                msg.body = f'There was an attempt to log in to your account. Please use this link to access the next step to log in to your account {link}. If this was not done by you. Please DO NOT share the link with anyone. Happy Blogging -FlaskerBlog'
                                mail.connect()
                                mail.send(msg)
                                flash('A Link Has Been Sent To Access Your Account. Please Follow The Steps To Access Your Account.','success')
                                session["username"] = username
                                return redirect(url_for('login'))
                            except socket.gaierror:
                                flash('No Connection Detected. Please Try Again', 'error')
                                return redirect(url_for('add_user'))
                            except smtplib.SMTPServerDisconnected:
                                flash('A Server Connection Has Occured. Please Try Again Later.','error')
                                return redirect(url_for('index'))
                            except OSError:
                                flash('A Network Connection Has Occured. Please Try Again Later.','error')
                                return redirect(url_for('index'))

                        elif form.login_method.data == "Phone Number":
                            try:
                                otp = random.randint(100000,999999)
                                name = decrypt_data(user.name)
                                client.messages.create(
                                body = f"Dear {name}, there was a request to Login to your account recently. If this was not done by you, your account may be under attack. Quickly Login and Change your Password. Your OTP is {otp} -FlaskerBlog.",
                                    from_= "+14242030414",
                                    to= tel_phone
                                )
                                session["username"] = username
                                session["otp"] = otp
                                flash('Please enter the OTP that was recently sent','warning')
                                return redirect(url_for('login_otp_verify'))
                            except twilio.base.exceptions.TwilioException:
                                flash('A Twilio Authentication Error has occured','error')
                                return redirect(url_for('login'))
                    else:
                        counter -= 1

                        user.counter = counter
                        db.session.commit()
                        flash('Wrong Password or Username', 'warning')
                        flash(f'Tries remaining: {counter}', 'warning')
                        form.username.data = ''
                        form.password.data = ''

                elif counter == 1:
                    flash('Maximum password attempts reached. Account has been locked out.', 'warning')
                    flash('Please follow the steps to reset your password and unlock your account.','warning')
                    return redirect(url_for('email_tel_verify_forgetpass'))

            else:
                flash('Wrong Password or Username','warning')

                form.username.data = ''
                form.password.data = ''

        return render_template('login.html',form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/dashboard_login/<token>', methods=["GET","POST"])
def dashboard_login(token):
    try:
        try:
            username = session["username"]
        except:
            flash('An error has occured while logging you into the dashboard. Please do not tamper with the URL.','error')
            return redirect(url_for('index'))

        user = Users.query.filter_by(username=username).first()
        if user:
            try:
                email= s.loads(token,salt='xm42l2$*2M2^%*(', max_age=300) #max_age in sec give def of 300 sec (5 min)
                login_user(user,remember=False)
                flash('You have successfully logged in using Email. Hope you enjoy using uur services','success')
                return redirect(url_for('dashboard'))
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('index'))
            except:
                flash('An unknown error has occurred. Please Try Again', 'error')
                return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/login_otp_verify', methods=["GET","POST"])
def login_otp_verify():
    try:
        try:
            username = session["username"]
        except:
            flash('Login Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))

        otp = session["otp"]
        if otp == None:
            flash('OTP has expired or is Invalid. Please try again. Check your details again carefully.','error')
            return redirect(url_for('login'))

        form = LoginOTPVerifyForm()
        if form.validate_on_submit():
            if form.loginotp.data == otp:
                user = Users.query.filter_by(username = username).first()
                tel_phone = user.tel_phone
                name = decrypt_data(user.name) #test here
                client.messages.create(
                body = f"Welcome {name}, You have successfully signed in to FlaskerBlog. If this was NOT you, please log in immediately to protct yur account. Have a wonderful time using our App. -FlaskerBlog ",
                    from_= "+14242030414",
                    to= tel_phone
                )
                session["otp"] = session.pop(otp,None)
                login_user(user, remember=False)
                flash('You have successfully logged in using SMS. Hope you enjoy using our services','success')
                return redirect(url_for('dashboard'))
            else:
                session["otp"] = session.pop(otp,None)
                flash('You Have Entered An Invalid OTP. Please Try Again', 'warning')
                return redirect(url_for('login'))
        return render_template('login_otp_verify.html',form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/expire_otp_login', methods=["GET","POST"])
def expire_otp_login():
    try:
        otp =session["otp"]
        session["otp"] = session.pop(otp,None)
        return redirect(url_for('login_otp_verify'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#END OF LOGIN FUNCTIONS
#-------------------------------------------------------------------------------------------------

#POSTS CRUD

#Create Post
@app.route('/add-post', methods=["GET","POST"])
@login_required
def add_post():
    try:
        form = PostsForm()
        if form.validate_on_submit():
            poster = current_user.id
            post = Posts(title= form.title.data, content=form.content.data, poster_id =poster, slug = form.slug.data)
            #clears form when submited
            form.title.data = ''
            form.content.data = ''
            form.slug.data = ''
            db.session.add(post)
            db.session.commit()
            #return msg
            flash('Blog Post Submitted Successfully')
        return render_template('add_post.html',
                               form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#Retrieve all Posts
@app.route('/posts')
def posts():
    try:
        #grab blog posts from db
        posts= Posts.query.order_by(Posts.date_posted)
        return render_template("posts.html",
                               posts=posts)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#Retrieve 1 post based on id
@app.route('/posts/<int:id>')
def post(id):
    try:
        post = Posts.query.get_or_404(id)
        username = post.poster.username
        about_author = post.poster.about_author
        username = decrypt_data(username)
        try:
            about_author = decrypt_data(about_author)
        except:
            about_author = ""
        return render_template('post.html',
                               post=post, attributes_name=username, attributes_about_author=about_author)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#Updating a post based on id
@app.route('/posts/edit/<int:id>', methods=["GET","POST"])
@login_required
def edit_post(id):
    try:
        post = Posts.query.get_or_404(id)
        form= PostsForm()
        if form.validate_on_submit():
            post.title= form.title.data
            post.slug = form.slug.data
            post.content = form.content.data
            #update db
            db.session.add(post)
            db.session.commit()
            #return msg
            flash("Post Updated Sucessfully")
            return redirect(url_for('post',id=post.id))
        if current_user.id == post.poster_id or current_user.id == 1:
            form.title.data= post.title
            form.slug.data = post.slug
            form.content.data = post.content
            return render_template('edit_post.html',
                                   form=form
                               )
        else:
            flash('You are not authorised to edit this post')
            #grab blog posts from db
            posts= Posts.query.order_by(Posts.date_posted)
            return render_template("posts.html",
                                   posts=posts)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/posts/delete/<int:id>')
@login_required
def delete_post(id):
    try:
        post_to_delete= Posts.query.get_or_404(id)
        id = current_user.id
        if id == post_to_delete.id or id == 1:
            try:
                db.session.delete(post_to_delete)
                db.session.commit()
                flash("Post Deleted Sucessfully!")
                #grab blog posts from db
                posts= Posts.query.order_by(Posts.date_posted)
                return render_template("posts.html",
                                       posts=posts)
            except:
                #return Err msg
                flash("Problem when Deleting Post",'error')
                #grab blog posts from db
                posts= Posts.query.order_by(Posts.date_posted)
                return render_template("posts.html",
                                       posts=posts)
        else:
            flash('You Cannot Delete Posts That Are Not Yours','error')
            #grab blog posts from db
            posts= Posts.query.order_by(Posts.date_posted)
            return render_template("posts.html",
                                   posts=posts)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#END OF POST CRUD
#------------------------------------------------------------------------------------------------

#CHANGE EMAIL FUNCTIONS
@app.route('/change_email', methods=["GET","POST"])
def change_email():
    try:
        form = ChangeEmailForm() #1 Done in webforms and change_email.html
        if form.validate_on_submit():
            tel_phone = form.countryCode.data+form.telnoverify.data
            user = Users.query.filter_by(tel_phone=tel_phone).first()
            if user:
                user_name = decrypt_data(user.name)
                user_email = user.email
                user_tel_phone = user.tel_phone #2 Find tel_phone linked to OLD Email CAN also use form.countryCode.data+form.telnoverify.data AKA tel_phone var
                if decrypt_data(user_email) == form.old_email.data: #1 Checking to see if email in db == old data
                    otp = random.randint(100000,999999)
                    client.messages.create( #3 Sent OTP using the tel_phone
                        body=f'Dear {user_name}, there was a request to change your email recently. If this was not done by you, your account may be under attack. Quickly Login and Change your Password. Your OTP is {otp}',
                            from_= "+14242030414",
                            to= user_tel_phone
                    )
                    session["name"] = user_name
                    session["otp"] = otp
                    session["email"] = form.new_email.data
                    session["tel_phone"] = user_tel_phone
                    flash('Please enter the OTP to continue','warning')
                    return redirect(url_for('otp_verify_change_email'))
                elif decrypt_data(user_email) != form.old_email.data:
                    flash('The Old email is not registered. Please create an account if you have not. Its Free','warning')
                    return redirect(url_for('add_user'))
                elif form.new_email.data == form.old_email.data:
                    flash('The New email CANNOT be the same as the Old email.','warning')
                    return redirect(url_for('change_email'))
            else:
                flash('This account is not registered. Please register for an account if you have not.','warning')
                return redirect(url_for('add_user'))
        return render_template('change_email.html',
                               form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/otp_verify_change_email', methods=["GET","POST"])
def otp_verify_change_email():
    try:
        try:
            name = session["name"]
            new_email = session["email"]
            tel_phone = session["tel_phone"]
        except:
            flash('Changing Email Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))
        otp = session["otp"]
        if otp == None:
            flash('OTP has expired or is Invalid. Please try again. Check your details again carefully.','error')
            return redirect(url_for('change_email'))

        form = OTPVerifyChangeEmailForm()
        if form.validate_on_submit():
            if form.changeemailotp.data == otp:
                try:
                    session["new_email"] = new_email
                    session["tel_phone"] = tel_phone
                    session["otp"] = session.pop(otp,None)
                    flash('To verify your identity, we would require you authenticate youself with Security Question. ','success')
                    return redirect(url_for('change_email_security_question_verify'))
                except TimeoutError:
                    session["otp"] = session.pop(otp,None)
                    flash('Request is taking too long too load. Please try again later', 'error')
                    return redirect(url_for('add_user'))
                except socket.gaierror:
                    session["otp"] = session.pop(otp,None)
                    flash('No Connection Detected. Please Try Again', 'error')
                    return redirect(url_for('index'))
                except smtplib.SMTPServerDisconnected:
                    session["otp"] = session.pop(otp,None)
                    flash('A Server Connection Has Occured. Please Try Again Later.','error')
                    return redirect(url_for('index'))
                except OSError:
                    session["otp"] = session.pop(otp,None)
                    flash('A Network Connection Has Occured. Please Try Again Later.','error')
                    return redirect(url_for('index'))
            else:
                session["otp"] = session.pop(otp,None)
                flash('OTP entered wrongly. Please try again','error')
                return redirect(url_for('change_email'))
        return render_template('otp_verify_change_email.html',form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/expire_otp_change_email', methods=["GET","POST"])
def expire_otp_change_email():
    try:
        otp =session["otp"]
        session["otp"] = session.pop(otp,None)
        return redirect(url_for('otp_verify_change_email'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/change_email_security_question_verify', methods=["GET","POST"])
def change_email_security_question_verify():
    try:
        form = VerifySecurityQuestion()
        try: #Check for URL Tampering
            new_email= session["new_email"]
            tel_phone= session["tel_phone"]
        except:
            flash('An error has occurred retrieving your details. Please do not manually enter this URL.','error')
            return redirect(url_for('index'))
        user = Users.query.filter_by(tel_phone = tel_phone).first()
        user_id = user.id
        user_security = UsersSecurityQuestion.query.filter_by(user_id = user_id).all()
        if user.user_secure_question_attempt != 1:
            if user_security:
                user_security_questions_list =[]
                user_security_answer_list = []
                for i in user_security:  #loops through each pass_user_id
                    answered_questions= i.security_question_id #Gets the actual data, which is teh security question id
                    answers = i.security_answer #Gets the actual data, which is the answer (In bytes format)
                    answers = decrypt_data(answers) #Decrypts the data above
                    user_security_questions_list.append(answered_questions) #Appends the questions to a list
                    user_security_answer_list.append(answers) #Appends the answers to a list

            # email_to_sent = decrypt_data(user_email)
                if form.validate_on_submit():
                    form.security_answer.data = [form.security_answer.data]
                    form.security_question.data = [form.security_question.data]

                    db_input = list(zip(user_security_answer_list,user_security_questions_list))
                    user_input = list(zip(form.security_answer.data,form.security_question.data))


                    for i in range(len(db_input)):
                        try:
                            if user_input[0] == db_input[i]:
                                flash('Thank you for verifying your identity','success')
                                flash('To change your email, we need to verify that it is an actual email. Please click on the link that is sent to your New email','warning')
                                #send email to new email
                                token = s.dumps(new_email, salt='@^zF7#u^16')
                                msg = Message(new_email,sender='FlaskerBlog@outlook.com', recipients=[new_email])
                                link = url_for('change_email_email_confirm',token= token,_external=True) #Add token
                                msg.body = f'There was an attempt to change your email at FlaskerBlog. Please use this link to change your email: {link}. If this was not done by you. Please DO NOT share the link with anyone. Happy Blogging -FlaskerBlog'
                                mail.connect()
                                mail.send(msg)
                                session["new_email"]= new_email
                                session["tel_phone"]= tel_phone
                                return redirect(url_for('change_email_security_question_verify'))
                            else:
                                i +=1
                                if i == len(db_input):
                                    security_attempt = user.user_secure_question_attempt
                                    if security_attempt == 1:
                                        flash('You have made too may failed attempts. Please try again.','error')
                                        email = decrypt_data(user.email)
                                        token = s.dumps(email, salt='H39(!6w89#$)B&N',)
                                        msg = Message(email,sender='FlaskerBlog@outlook.com', recipients=[email])
                                        link = url_for('reset_security_question_change_email_verify', token=token, _external=True)
                                        msg.body = f'Dear user, there was an attempt to change your email at FlaskerBlog. You are receiving this email because there were too many fail attempts. If you have forgotten your security questions and answers, please use this link: {link}. If this was not you, please log back in immediately and change your password. -FlaskerBlog'
                                        mail.connect()
                                        mail.send(msg)
                                        #send email
                                        session["new_email"]= new_email
                                        session["tel_phone"]= tel_phone
                                        session["user_id"] = user.id
                                        return redirect(url_for('index'))
                                    else:
                                        user.user_secure_question_attempt -= 1
                                        db.session.commit()
                                        flash('You have entered the wrong answer for that question. Please check your answer again.','warning')
                                        flash('Remember that the answer is Case-Sensitive','info')
                                        return redirect(url_for('change_email_security_question_verify'))

                        except IndexError:
                            flash('You have entered the wrong answer for that question. Please check your answer again.','warning')
                            flash('Remember that the answer is Case-Sensitive','info')
                            return redirect(url_for('change_tel_phone_security_question_verify'))

                        except twilio.base.exceptions.TwilioRestException:
                            flash('This number is not registered in our Twilio database, and therefore, this number cannot be used.','error')
                            return redirect(url_for('index'))

                else:
                    return render_template('change_email_security_question_verify.html'
                               , form=form) #renders the page where user can choose their preferred 2FA option

            else:
                flash('We detected that you do not have a Security Question 2FA. In order to change your phone number, we require you to implement it.','warning')
                return redirect(url_for('add_security_question'))
        else:
            email = decrypt_data(user.email)
            #send email
            token = s.dumps(email, salt='6&t(9Eo510^i#y^',)
            msg = Message(email,sender='FlaskerBlog@outlook.com', recipients=[email])
            link = url_for('reset_security_question_change_email_verify', token=token, _external=True)
            msg.body = f'Dear user, your account has been suspended from changing account details and therefore, you are unable to change your password. If you have forgotten your security questions and answers, please use this link: {link}. -FlaskerBlog'
            mail.connect()
            mail.send(msg)
            session["user_id"] = user.id
            session["tel_phone"]= tel_phone
            flash('You have reached the maximum number of attempts and therfore, have been suspended from changing account details. Please follow the steps in your email to reset your account security questions.','warning')
            return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/reset_security_question_change_email_verify/<token>', methods=["GET","POST"])
def reset_security_question_change_email_verify(token):
    try:
        if request.method == "GET":
            try:
                user_id= session["user_id"]
                new_email= session["new_email"]
                tel_phone=  session["tel_phone"]
                email = s.loads(token,salt='H39(!6w89#$)B&N', max_age=300)
                flash('Please follow the steps to reset your security question', 'info')
                session["user_id"]= user_id
                return redirect(url_for('reset_security_question_change_email'))
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('index'))
            except:
                flash('Adding Account Process Done Incorrectly. Please Do Not Tamper With The URL','error')
                return redirect(url_for('index'))
        else:
            flash('An Error Has Occured When Verifying Email. Please Try Again Later', 'error')
            return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/reset_security_question_change_email',methods=["GET","POST"])
def reset_security_question_change_email():
    try:
        form = SecurityQuestion()
        try:
            userid = session["user_id"]
        except:
            flash('Resetting Security Questions Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))
        if form.validate_on_submit():
            user_security_question = form.security_question.data
            user_security_answer = form.security_answer.data
            user = Users.query.filter_by(id=userid).first() #Filers using the users id
            if user:
                user_id = user.id
                user_security = UsersSecurityQuestion.query.filter_by(user_id = user_id).all()
                user.user_secure_question_attempt = 3
                db.session.commit()
                if not user_security: #User has no question in db
                    user_security = UsersSecurityQuestion(security_question_id= user_security_question,security_answer=encrypt_data(generate_salt(),user_security_answer),user_id = user_id)
                    db.session.add(user_security)
                    db.session.commit()
                    flash('Successfully added in your first 2FA security question.','success')
                    return redirect(url_for('change_email_security_question_verify'))
                elif user_security: #User has a question in db

                    user_security_questions_list =[]
                    for i in user_security:  #loops through each pass_user_id
                        answered_questions= i.security_question_id
                        user_security_questions_list.append(answered_questions)
                    for i in range(len(user_security_questions_list)):
                        if user_security_question == user_security_questions_list[i]:
                            flash('Your new answer has been saved successfully .','warning')
                            user_security[i].security_question_id = user_security_questions_list[i]

                            user_security[i].security_answer = encrypt_data(generate_salt(),user_security_answer)
                            db.session.commit()
                            return redirect(url_for('change_email_security_question_verify'))
                        else:
                            i +=1
                            if i == len(user_security_questions_list):
                                user_security = UsersSecurityQuestion(security_question_id= user_security_question,
                                                                      security_answer=encrypt_data(generate_salt(),user_security_answer),user_id = user_id)
                                db.session.add(user_security)
                                db.session.commit()
                                flash('New security question 2FA successfully added','success')
                                return redirect(url_for('change_email_security_question_verify'))

            else:
                flash('In order to create security question 2FA, you would need to have an account','warning')
                return redirect(url_for('add_user'))
        else:
            return render_template('add_security_question.html',form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/change_email_email_confirm/<token>', methods=["GET","POST"])
def change_email_email_confirm(token):
    try:
        if request.method == "GET":
            try:
                email = session["new_email"]
                tel_phone= session["tel_phone"]
            except:
                flash('Changing Email Process Done Incorrectly. Please Do Not Tamper With The URL','error')
                return redirect(url_for('index'))

            try:
                email = s.loads(token,salt='@^zF7#u^16',max_age= 300 ) #max_age in sec give drf of 300 sec (5 min)
                flash('Email has been verified','success')
                return redirect(url_for('email_changed'))
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('index'))
        else:
            flash('An Error Has Occured When Verifying Email. Please Try Again Later', 'error')
            return redirect(url_for('index'))

    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/email_changed',methods=["GET","POST"])
def email_changed():
    try:
        try:
            new_email = session["new_email"]
            tel_phone = session["tel_phone"]
        except:
            flash('Email Change Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))

        user = Users.query.filter_by(tel_phone = tel_phone).first()
        user.email = encrypt_data(generate_salt(),new_email)
        db.session.commit()
        flash('Email has been changed sucessfully','success')
        name = decrypt_data(user.name)
        client.messages.create( #3 Sent OTP using the tel_phone
            body=f'Dear {name}, Your email has been changed successfully. If this was not done by you, your account may be under attack. Quickly Login and Change your Password.',
                from_= "+14242030414",
                to= tel_phone
            )
        return redirect(url_for('login'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#END OF CHANGE EMAIL FUNCTION
#-------------------------------------------------------------------------------------------------

#CHANGE PHONE NUMBER

#Change tel_phone psudo code:
#1) User is asked to enter Registered Email, Old Phone Num and New Phone Num
#2) Uses the old tel_phone as a filter by option
#3) Gets the email in the db
#4) Checks if the email in db == user entered email
#5) If both ==, send email confirmation to email.
    #6) If not ==, sends both email to the registered val in db to warn user.
#7) When email confirm link is clicked, Additional Verification check is needed
    #8 Additional check can be:
        #1) Security Question
        # Note that email is not usable as if email goes through the previous function, assuming hacker ha control of email, unwise to sent all through email
        # Note that old phone number CANNOT as the old numbers gets reassigned to other people
    #9) If Additional Verification fails, send alert to registered email
#10) If Verification Succeed.
    #11) Update tel_phone number, use old_tel_phone as filter


@app.route('/change_tel_phone', methods=["GET","POST"])
def change_tel_phone():
    try:
        form = ChangeTelForm()
        if form.validate_on_submit():
            old_tel_phone = form.old_countryCode.data+form.old_telno.data
            user = Users.query.filter_by(tel_phone=old_tel_phone).first()
            if user: #Checks if the user valid
                user_name = decrypt_data(user.name)
                user_email = user.email
                user_tel_phone = user.tel_phone
                user_new_tel_phone = form.new_countryCode.data+form.new_telno_verify.data
                if decrypt_data(user_email) != form.email.data: #Email is not register
                    try:
                        user_send_email = decrypt_data(user_email)
                        msg = Message(user_send_email, sender='FlaskerBlog@outlook.com', recipients=[user_send_email])
                        msg.body = 'Dear user, there was a request to change your phone number recently. However, you are receiving this email as the details entered were incorrect. If you did not request a change of your phone number, please log in immediately and change your password.'
                        mail.connect()
                        mail.send(msg)
                        flash('The details are incorrect. Please try again.','warning')
                        return redirect(url_for('change_tel_phone'))
                    except:
                        flash('An error has occured. Please try again later','error')
                if user_tel_phone == user_new_tel_phone: #Checks if tel_phone in db == user new tel_phone
                    flash('The New phone number CANNOT be the same as your old phone number.','warning')
                    return redirect(url_for('change_tel_phone'))
                elif decrypt_data(user_email) == form.email.data: #1 Checking to see if email in db == data
                    # try:
                        user_send_email = decrypt_data(user_email)
                        token = s.dumps(user_send_email, salt='xm42l2$*2M2^%*(',)
                        msg = Message(user_send_email, sender='FlaskerBlog@outlook.com', recipients=[user_send_email])
                        link = url_for('change_tel_phone_email_confirm', token=token, _external=True)
                        msg.body = f'If you are not the one changing your phone number, we would advise you to log in immediately and change your password. ' \
                                   f'The link to change your email is: {link}. ' \
                                   f'Thank you for using FlaskerBlog -FlaskerBlog.'
                        session["name"] = user_name
                        session["email"] = user_email
                        session["old_tel_phone"] = user_tel_phone
                        session["new_tel_phone"] = user_new_tel_phone
                        mail.connect()
                        mail.send(msg)
                        flash('An email has been sent to you. Please use the link to change your phone number.','success')
                    # except:
                    #     flash('An Error has occured. Please try again later','error')
            else:
                flash('The details are incorrect. Please try again.','warning')
                return redirect(url_for('change_tel_phone'))
        return render_template('change_tel_phone.html',
                               form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

# If form.2FA_method == "Email" This app.route acts as a buffer zone. This is where the expiry of email link is
@app.route('/change_tel_phone_email_confirm/<token>', methods=["GET","POST"])
def change_tel_phone_email_confirm(token):
    try:
        if request.method == "GET":
            try:
                email = session["email"]
                email = s.loads(token,salt='xm42l2$*2M2^%*(', max_age=300) #max_age in sec give drf of 300 sec (5 min)
                user_tel_phone = session["old_tel_phone"]
                user_new_tel_phone = session["new_tel_phone"]
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('index'))
            except:
                flash('An error has occurred retrieving your details. Please do not manually enter this URL.','error')
                return redirect(url_for('index'))
            try:
                flash('Email 2FA successful. Thank You for verifying your identity', 'success')
                flash('To fully verify your identity, we would need you to authenticate yourself by answering a security question','info')
                session["old_tel_phone"]  = user_tel_phone
                session["new_tel_phone"]  = user_new_tel_phone
                return redirect(url_for('change_tel_phone_security_question_verify'))
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('add_user'))

        else:
            flash('An Error Has Occured When Verifying Email. Please Try Again Later', 'error')
            return redirect(url_for('add_user'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/change_tel_phone_security_question_verify', methods=["GET","POST"])
def change_tel_phone_security_question_verify():
    try:
        form = VerifySecurityQuestion()
        try: #Check for URL Tampering
            user_tel_phone = session["old_tel_phone"]
            user_new_tel_phone = session["new_tel_phone"]
        except:
            flash('An error has occurred retrieving your details. Please do not manually enter this URL.','error')
            return redirect(url_for('index'))
        user = Users.query.filter_by(tel_phone = user_tel_phone).first()
        user_id = user.id
        user_security = UsersSecurityQuestion.query.filter_by(user_id = user_id).all()
        if user.user_secure_question_attempt != 1:
            if user_security:
                user_security_questions_list =[]
                user_security_answer_list = []
                for i in user_security:  #loops through each pass_user_id
                    answered_questions= i.security_question_id #Gets the actual data, which is teh security question id
                    answers = i.security_answer #Gets the actual data, which is the answer (In bytes format)
                    answers = decrypt_data(answers) #Decrypts the data above
                    user_security_questions_list.append(answered_questions) #Appends the questions to a list
                    user_security_answer_list.append(answers) #Appends the answers to a list

                #Use the print statements below to see Answers and Questions stored in the DB (Decrypted)
                # print('Answered Questions:',user_security_questions_list)
                # print('Answers to questions',user_security_answer_list)

            # email_to_sent = decrypt_data(user_email)
                if form.validate_on_submit():
                    form.security_answer.data = [form.security_answer.data]
                    form.security_question.data = [form.security_question.data]

                    db_input = list(zip(user_security_answer_list,user_security_questions_list))
                    user_input = list(zip(form.security_answer.data,form.security_question.data))

                    #Use the below print statements to see the Users input and database values
                    # print('user input using zip',user_input)
                    # print('answer and question in db using zip',db_input)

                    for i in range(len(db_input)):
                        try:
                            #Use the below statements to see the if condition
                            # print(user_input)
                            # print(db_input[i])
                            # print('if statement logic: ',user_input[0], '==',db_input[i])
                            if user_input[0] == db_input[i]:
                                # print('Was the statement a match: Yes')
                                flash('Thank you for verifying your identity','success')
                                flash('To add your new phone number, we need to verify that it is an actual phone number. Please enter the OTP that is sent to your New phone number','warning')
                                session["old_tel_phone"] = user_tel_phone
                                session["new_tel_phone"] = user_new_tel_phone
                                #send msg to new_tel_phone, pass otp var here
                                otp = random.randint(100000,999999)
                                name = decrypt_data(user.name)
                                client.messages.create( #3 Sent OTP using the tel_phone
                                    body=f'Dear {name}, To verify your new phone number, please enter this OTP {otp}',
                                    from_= "+14242030414",
                                    to= user_new_tel_phone
                                )
                                session["otp"]= otp
                                return redirect(url_for('otp_verify_change_tel_phone'))
                            else:
                                i +=1
                                # print('Was the statement a match: No')
                                if i == len(db_input):
                                    security_attempt = user.user_secure_question_attempt
                                    if security_attempt == 1:
                                        flash('You have made too many failed attempts. Please try again.','error')
                                        email = decrypt_data(user.email)
                                        token = s.dumps(email, salt='2$a3W^$BE295!#t',)
                                        msg = Message(email,sender='FlaskerBlog@outlook.com', recipients=[email])
                                        link = url_for('reset_security_change_tel_phone', token=token, _external=True)
                                        msg.body = f'Dear user, there was an attempt to change your phone number at FlaskerBlog. You are receiving this email because there were too many fail attempts. If you have forgotten your security questions and answers, please use this link: {link}. If this was not you, please log back in immediately and change your password. -FlaskerBlog'
                                        mail.connect()
                                        mail.send(msg)
                                        session["old_tel_phone"] = user_tel_phone
                                        session["new_tel_phone"] = user_new_tel_phone
                                        session["user_id"] = user.id
                                        return redirect(url_for('index'))
                                    else:
                                        user.user_secure_question_attempt -= 1
                                        db.session.commit()
                                        flash('You have entered the wrong answer for that question. Please check your answer again.','warning')
                                        flash('Remember that the answer is Case-Sensitive','info')
                                        return redirect(url_for('change_tel_phone_security_question_verify'))

                        except IndexError:
                            flash('You have entered the wrong answer for that question. Please check your answer again.','warning')
                            flash('Remember that the answer is Case-Sensitive','info')
                            return redirect(url_for('change_tel_phone_security_question_verify'))

                        except twilio.base.exceptions.TwilioRestException:
                            flash('This number is not registered in our Twilio database, and therefore, this number cannot be used.','error')
                            return redirect(url_for('index'))
                        except:
                            flash('An unexpected error has occured. Please try again','error')
                            return redirect(url_for('index'))

                else:
                    return render_template('change_tel_phone_security_question_verify.html'
                               , form=form) #renders the page where user can choose their preferred 2FA option

            else:
                flash('We detected that you do not have a Security Question 2FA. In order to change your phone number, we require you to implement it.','warning')
                return redirect(url_for('add_security_question'))

        else:
            email = decrypt_data(user.email)
            #send email
            token = s.dumps(email, salt='2$a3W^$BE295!#t',)
            msg = Message(email,sender='FlaskerBlog@outlook.com', recipients=[email])
            link = url_for('reset_security_change_tel_phone', token=token, _external=True)
            msg.body = f'Dear user, your account has been suspended from changing account details, and therefore, are unable to change your phone number. If you have forgotten your security questions and answers, please use this link: {link}. -FlaskerBlog'
            mail.connect()
            mail.send(msg)
            session["user_id"] = user.id
            session["old_tel_phone"] = user_tel_phone
            session["new_tel_phone"] = user_new_tel_phone
            flash('We have suspended your account from changing account details. Please follow the steps in your email to unlock your account.','warning')
            return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/reset_security_change_tel_phone/<token>', methods=["GET","POST"])
def reset_security_change_tel_phone(token):
    try:
        if request.method == "GET":
            try:
                user_id = session["user_id"]
                session["user_id"] = user_id
                user_tel_phone= session["old_tel_phone"]
                user_new_tel_phone= session["new_tel_phone"]
                email = s.loads(token,salt='2$a3W^$BE295!#t', max_age=300) #max_age in sec give drf of 300 sec (5 min)
                flash('Please follow the steps to reset your security question', 'info')
                return redirect(url_for('reset_security_question_change_tel'))
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('index'))
            except:
                flash('Adding Account Process Done Incorrectly. Please Do Not Tamper With The URL','error')
                return redirect(url_for('index'))
        else:
            flash('An Error Has Occured When Verifying Email. Please Try Again Later', 'error')
            return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/reset_security_question_change_tel',methods=["GET","POST"])
def reset_security_question_change_tel():
    try:
        form = SecurityQuestion()
        try:
            userid = session["user_id"]
        except:
            flash('Resetting Security Questions Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))


        if form.validate_on_submit():
            user_security_question = form.security_question.data
            user_security_answer = form.security_answer.data
            user = Users.query.filter_by(id=userid).first() #Filers using the users id
            if user:
                user_id = user.id
                user_security = UsersSecurityQuestion.query.filter_by(user_id = user_id).all()
                user.user_secure_question_attempt = 3
                db.session.commit()
                if not user_security: #User has no question in db
                    user_security = UsersSecurityQuestion(security_question_id= user_security_question,security_answer=encrypt_data(generate_salt(),user_security_answer),user_id = user_id)
                    db.session.add(user_security)
                    db.session.commit()
                    flash('Successfully added in your first 2FA security question.','success')
                    return redirect(url_for('change_tel_phone_security_question_verify'))
                elif user_security: #User has a question in db

                    user_security_questions_list =[]
                    for i in user_security:  #loops through each pass_user_id
                        answered_questions= i.security_question_id
                        user_security_questions_list.append(answered_questions)
                    for i in range(len(user_security_questions_list)):
                        if user_security_question == user_security_questions_list[i]:
                            flash('Your new answer has been saved successfully .','warning')
                            user_security[i].security_question_id = user_security_questions_list[i]

                            user_security[i].security_answer = encrypt_data(generate_salt(),user_security_answer)
                            db.session.commit()
                            return redirect(url_for('change_tel_phone_security_question_verify'))
                        else:
                            i +=1
                            if i == len(user_security_questions_list):
                                user_security = UsersSecurityQuestion(security_question_id= user_security_question,
                                                                      security_answer=encrypt_data(generate_salt(),user_security_answer),user_id = user_id)
                                db.session.add(user_security)
                                db.session.commit()
                                flash('New security question 2FA successfully added','success')
                                return redirect(url_for('change_tel_phone_security_question_verify'))

            else:
                flash('In order to create security question 2FA, you would need to have an account','warning')
                return redirect(url_for('add_user'))
        else:
            return render_template('add_security_question.html',form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/otp_verify_change_tel_phone', methods=["GET","POST"]) #This is where the changes to the tel_phone will occur
def otp_verify_change_tel_phone():
    try:
        try:
            user_tel_phone = session["old_tel_phone"]
            user_new_tel_phone = session["new_tel_phone"]
        except:
            flash('An error has occurred retrieving your details. Please do not manually enter this URL.','error')
            return redirect(url_for('lndex'))
        otp = session["otp"]
        if otp == None:
            flash('OTP has expired or is Invalid. Please try again. Check your details again carefully.','error')
            return redirect(url_for('change_tel_phone_security_question_verify'))

        user = Users.query.filter_by(tel_phone= user_tel_phone).first()
        form = OTPVerifyChangetelPhoneForm()
        if form.validate_on_submit():
            if form.changetelphoneotp.data == otp:
                try:
                    user.tel_phone = user_new_tel_phone
                    db.session.commit()
                    session["otp"] = session.pop(otp,None)
                    email = decrypt_data(user.email)
                    msg = Message(email,sender='FlaskerBlog@outlook.com', recipients=[email])
                    msg.body = f'Your phone number has been successfully changed to {user_new_tel_phone}. If this was not done by you, change your phone number back. -FlaskerBlog'
                    mail.connect()
                    mail.send(msg)

                    client.messages.create(
                    body=f'Dear user, Your phone number has been changed successfully. If this was not done by you, change your phone number back.',
                        from_= "+14242030414",
                        to= user_new_tel_phone
                    )
                    flash('Your phone number has been changed successfully.','success')
                    return redirect(url_for('index'))
                except TimeoutError:
                    session["otp"] = session.pop(otp,None)
                    flash('Request is taking too long too load. Please try again later', 'error')
                    return redirect(url_for('index'))
                except socket.gaierror:
                    session["otp"] = session.pop(otp,None)
                    flash('No Connection Detected. Please Try Again', 'error')
                    return redirect(url_for('index'))
                except OSError:
                    session["otp"] = session.pop(otp,None)
                    flash('A Network Connection Has Occured. Please Try Again Later.','error')
                    return redirect(url_for('index'))
            else:
                session["otp"] = session.pop(otp,None)
                flash('OTP entered wrongly. Please try again','error')
                return redirect(url_for('index'))
        return render_template('otp_verify_change_tel_phone.html',form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/expire_otp_change_tel_phone', methods=["GET","POST"])
def expire_otp_change_tel_phone():
    try:
        otp =session["otp"]
        session["otp"] = session.pop(otp,None)
        return redirect(url_for('otp_verify_change_email'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/tel_phone_changed',methods=["GET","POST"])
def tel_phone_changed():
    try:
        try:
            name = session["name"]
            new_email = session["new_email"]
            tel_phone = session["tel_phone"]
        except:
            flash('Email Change Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))

        user = Users.query.filter_by(tel_phone = tel_phone).first()
        user.email = encrypt_data(generate_salt(),new_email)
        db.session.commit()
        flash('Email has been changed sucessfully','success')
        client.messages.create( #3 Sent OTP using the tel_phone
            body=f'Dear {name}, Your email has been changed successfully. If this was not done by you, your account may be under attack. Quickly Login and Change your Password.',
                from_= "+14242030414",
                to= tel_phone
            )
        return redirect(url_for('login'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
#END OF CHANGE PHONE NUMBER FUNCTIONS
#----------------------------------------------------------------------------------------------------

#CHANGE/FORGET PASSWORD
@app.route('/email_tel_verify_forgetpass', methods=["GET","POST"])
def email_tel_verify_forgetpass():
    try:
        form = Email_Tel_VerifyForm()
        if form.validate_on_submit():
            ### REMEMBER TO COMBINE countryCode and telno to form the tel_phone data
            # otp shld sent to phone num or email IN db. Do a check algo. Psudo code as follows:
            #1) Check the db using the phone number Completed
            #2) Now that db is filtered for that 1 specific user, Check to see if user.email == form.email_verify.data
                #3) user.email refers to the email that the user has registerd. Assume this is users trusted email
                ##4) IF user.email != form.email_verify.data This means that the email entered is not the email that user has registered. Something may not be right
                    #5) Send an OTP to tel_phone --> To check if the user is the one trying to change password but from a different email (Could happen)
                    #6) Requires a Separate route for checking
                    #7) If the OTP matches, Safe to say, this is the real user
                        #8) Redirects to the forget_pass function for changing pass
            tel_phone = form.countryCode.data+form.telnoverify.data
            user = Users.query.filter_by(tel_phone =tel_phone).first()
            if user:
                db_user_email = decrypt_data(user.email)
                email_to_send = form.email_verify.data
                if email_to_send == db_user_email: #2 Checking if the entered email == registered email --> Matches
                    try:
                        token = s.dumps(email_to_send, salt='0#!7^z@4Bq43!&')
                        #a
                        msg = Message(email_to_send,sender='flaskerblog@outlook.com', recipients=[email_to_send])
                        link = url_for('forget_pass_email_verify',token=token ,_external=True)
                        msg.body = 'Dear Valued User, This is the link to reset your password. Do not share this link with anybody. {}'.format(link)
                        mail.connect()
                        mail.send(msg)
                        session["tel_phone"] = tel_phone #To be used in def forgot_pass as a filter_by()
                        flash('An email has been sent to your email address. Please click on the link to verify your email and follow the steps to change your password.','success')
                        return redirect(url_for('email_tel_verify_forgetpass'))
                    except socket.gaierror:
                        flash('No Connection Detected. Please Try Again', 'error')
                        return redirect(url_for('add_user'))
                    except smtplib.SMTPServerDisconnected:
                        flash('A Server Connection Has Occured. Please Try Again Later.','error')
                        return redirect(url_for('index'))
                    except OSError:
                        flash('A Network Connection Has Occured. Please Try Again Later.','error')
                        return redirect(url_for('index'))
                    except smtplib.SMTPAuthenticationError:
                        flash('Our Email Service Is Temporarily Unavailable. Please Try Again Later.','error')
                        return redirect(url_for('index'))
                elif email_to_send != db_user_email:
                    tel_phone = user.tel_phone
                    session["tel_phone"] = tel_phone
                    otp = random.randint(100000,999999)
                    name = decrypt_data(user.name)
                    client.messages.create(
                    body = f"Dear {name}, there was a request to Change Password recently. If this was not done by you, your account may be under attack. Quickly Login and Change your Password. Your OTP is {otp} -FlaskerBlog.",
                        from_= "+14242030414",
                        to= tel_phone
                    )
                    session["tel_phone"] = tel_phone
                    session["otp"] = otp

                    flash('The email you entered is not your Registered Email. As a Security Precaution, we would need to verify your identity. An OTP will be sent via SMS.','warning')
                    return redirect(url_for('otp_verify_forget_pass'))
            else:
                flash('This is not a registered account..', 'error')
                return redirect(url_for('add_user'))
        else:
            return render_template('email_tel_verify_forgetpass.html',
                                   form=form,
                                   )
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/forgot_pass_email_verify/<token>', methods=["GET","POST"])
def forget_pass_email_verify(token):
    try:
        if request.method == "GET":
            try:
                tel_phone = session["tel_phone"]
                email = s.loads(token,salt='0#!7^z@4Bq43!&', max_age=300) #max_age in sec give drf of 300 sec (5 min)
                session["tel_phone"] = tel_phone
                flash('To verify your identity, we would require you to authenticate yourself using Security Question', 'info')
                return redirect(url_for('forgot_pass_security_question_verify'))
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('index'))
            except:
                flash('Adding Account Process Done Incorrectly. Please Do Not Tamper With The URL','error')
                return redirect(url_for('index'))
        else:
            flash('An Error Has Occured When Verifying Email. Please Try Again Later', 'error')
            return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/otp_verify_forget_pass', methods=["GET","POST"])
def otp_verify_forget_pass():
    try:
        form = OTPVerifyForgetPassForm()
        otp = session["otp"]
        if otp == None:
            flash('OTP has expired or is Invalid. Please try again. Check your details again carefully.','error')
            return redirect(url_for('email_tel_verify_forgetpass'))

        tel_phone = session["tel_phone"]

        if form.validate_on_submit():
            if form.forgetpassotp.data == session["otp"]:
                session["tel_phone"] = tel_phone
                session["otp"] = session.pop(otp,None)
                flash('To verify your identity, we would require you to authenticate yourself using Security Question', 'info')
                return redirect(url_for('forgot_pass_security_question_verify'))
            else:
                session["otp"] = session.pop(otp,None)
                flash('OTP is incorrect. This OTP is now Invalid. Please check your details again carefully','error')
                return redirect(url_for('email_tel_verify_forgetpass'))
        return render_template('otp_verify_forget_pass.html',
                               form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/expire_otp_forget_pass', methods=["GET","POST"])
def expire_otp_forget_pass():
    try:
        otp =session["otp"]
        session["otp"] = session.pop(otp,None)
        return redirect(url_for('otp_verify_forget_pass'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/forgot_pass_security_question_verify', methods=["GET","POST"])
def forgot_pass_security_question_verify():
    try:
        form = VerifySecurityQuestion()
        try: #Check for URL Tampering
            tel_phone = session["tel_phone"]
        except:
            flash('An error has occurred retrieving your details. Please do not manually enter this URL.','error')
            return redirect(url_for('index'))
        user = Users.query.filter_by(tel_phone = tel_phone).first()
        user_id = user.id
        user_security = UsersSecurityQuestion.query.filter_by(user_id = user_id).all()
        security_attempt = user.user_secure_question_attempt
        if user.user_secure_question_attempt != 1:
            if user_security:
                user_security_questions_list =[]
                user_security_answer_list = []
                for i in user_security:  #loops through each pass_user_id
                    answered_questions= i.security_question_id #Gets the actual data, which is teh security question id
                    answers = i.security_answer #Gets the actual data, which is the answer (In bytes format)
                    answers = decrypt_data(answers) #Decrypts the data above
                    user_security_questions_list.append(answered_questions) #Appends the questions to a list
                    user_security_answer_list.append(answers) #Appends the answers to a list

            # email_to_sent = decrypt_data(user_email)
                if form.validate_on_submit():
                    form.security_answer.data = [form.security_answer.data]
                    form.security_question.data = [form.security_question.data]

                    db_input = list(zip(user_security_answer_list,user_security_questions_list))
                    user_input = list(zip(form.security_answer.data,form.security_question.data))

                    for i in range(len(db_input)):
                        try:
                            if user_input[0] == db_input[i]:
                                flash('Thank you for verifying your identity','success')
                                flash('To change your password, Please following the requirements as well as policy stated.','warning')
                                session["tel_phone"]= tel_phone
                                return redirect(url_for('forgot_pass'))
                            else:
                                i +=1
                                if i == len(db_input):
                                    if security_attempt == 1:
                                        flash('You have made too may failed attempts. Please try again.','error')
                                        email = decrypt_data(user.email)
                                        token = s.dumps(email, salt='H39(!6w89#$)B&N',)
                                        msg = Message(email,sender='FlaskerBlog@outlook.com', recipients=[email])
                                        link = url_for('reset_security_question', token=token, _external=True)
                                        msg.body = f'Dear user, there was an attempt too change your phone number at FlaskerBlog. You are receiving this email because there were too many fail attempts. If you have forgotten your security questions and answers, please use this link: {link}. If this was not you, please log back in immediately and change your password. -FlaskerBlog'
                                        mail.connect()
                                        mail.send(msg)
                                        #send email
                                        session["user_id"] = user.id
                                        return redirect(url_for('index'))
                                    else:
                                        user.user_secure_question_attempt -= 1
                                        db.session.commit()
                                        flash('You have entered the wrong answer for that question. Please check your answer again.','warning')
                                        flash('Remember that the answer is Case-Sensitive','info')
                                        return redirect(url_for('forgot_pass_security_question_verify'))

                        except IndexError:
                            flash('You have entered the wrong answer for that question. Please check your answer again.','warning')
                            flash('Remember that the answer is Case-Sensitive','info')
                            return redirect(url_for('forgot_pass_security_question_verify'))

                        except twilio.base.exceptions.TwilioRestException:
                            flash('This number is not registered in our Twilio database, and therefore, this number cannot be used.','error')
                            return redirect(url_for('index'))
                        except:
                            flash('An unexpected error has occured. Please try again','error')
                            return redirect(url_for('index'))

                else:
                    return render_template('change_tel_phone_security_question_verify.html'
                               , form=form) #renders the page where user can choose their preferred 2FA option

            else:
                flash('We detected that you do not have a Security Question 2FA. In order to change your phone number, we require you to implement it.','warning')
                session["user_id"] = user_id
                return redirect(url_for('reset_security_question_forgot_pass'))
        else:
            email = decrypt_data(user.email)
            #send email
            token = s.dumps(email, salt='6&t(9Eo510^i#y^',)
            msg = Message(email,sender='FlaskerBlog@outlook.com', recipients=[email])
            link = url_for('reset_security_question_forget_pass_email_verify', token=token, _external=True)
            msg.body = f'Dear user, your account has been suspended from changing account details and therefore, you are unable to change your password. If you have forgotten your security questions and answers, please use this link: {link}. -FlaskerBlog'
            mail.connect()
            mail.send(msg)
            #send email
            session["user_id"] = user.id
            session["tel_phone"]= tel_phone
            flash('You have reached the maximum number of attempts we have suspended you from changing account details. Please follow the steps in your email to reset your account security questions.','warning')
            return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/reset_security_question_forget_pass_email_verify/<token>', methods=["GET","POST"])
def reset_security_question_forget_pass_email_verify(token):
    try:
        if request.method == "GET":
            try:
                user_id= session["user_id"]
                tel_phone=  session["tel_phone"]
                email = s.loads(token,salt='6&t(9Eo510^i#y^', max_age=300) #max_age in sec give drf of 300 sec (5 min)
                flash('Please follow the steps to reset your security question', 'info')
                session["user_id"]= user_id
                return redirect(url_for('reset_security_question_forgot_pass'))
            except BadTimeSignature:
                flash('Your Email Verification Link Has Expired! Try Again', 'error')
                return redirect(url_for('index'))
            except:
                flash('Adding Account Process Done Incorrectly. Please Do Not Tamper With The URL','error')
                return redirect(url_for('index'))
        else:
            flash('An Error Has Occured When Verifying Email. Please Try Again Later', 'error')
            return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/reset_security_question_forgot_pass',methods=["GET","POST"])
def reset_security_question_forgot_pass():
    try:
        form = SecurityQuestion()
        try:
            userid = session["user_id"]
        except:
            flash('Reseting Security Questions Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))
        user = Users.query.filter_by(id=userid).first() #Filers using the users id
        user_id = userid
        user_security = UsersSecurityQuestion.query.filter_by(user_id = user_id).all()

        user_security_questions_list =[]
        user_security_answer_list = []
        for i in user_security:  #loops through each pass_user_id
            answered_questions= i.security_question_id #Gets the actual data, which is teh security question id
            answers = i.security_answer #Gets the actual data, which is the answer (In bytes format)
            answers = decrypt_data(answers) #Decrypts the data above
            user_security_questions_list.append(answered_questions) #Appends the questions to a list
            user_security_answer_list.append(answers) #Appends the answers to a list

        if form.validate_on_submit():
            user_security_question = form.security_question.data
            user_security_answer = form.security_answer.data
            if user:

                db.session.commit()
                if not user_security: #User has no question in db
                    user_security = UsersSecurityQuestion(security_question_id= user_security_question,security_answer=encrypt_data(generate_salt(),user_security_answer),user_id = user_id)
                    db.session.add(user_security)
                    db.session.commit()
                    user.user_secure_question_attempt = 3
                    db.session.commit()
                    flash('Successfully added in your first 2FA security question.','success')

                    return redirect(url_for('forgot_pass_security_question_verify'))
                elif user_security: #User has a question in db

                    for i in range(len(user_security_questions_list)):
                        if ( user_security_question == user_security_questions_list[i] ):
                            flash('Your new answer has been saved successfully.','success')
                            user_security[i].security_question_id = user_security_questions_list[i]

                            user_security[i].security_answer = encrypt_data(generate_salt(),user_security_answer)
                            db.session.commit()
                            user.user_secure_question_attempt = 3
                            db.session.commit()
                            return redirect(url_for('forgot_pass_security_question_verify'))
                        else:
                            i +=1
                            if i == len(user_security_questions_list):
                                user_security = UsersSecurityQuestion(security_question_id= user_security_question,
                                                                      security_answer=encrypt_data(generate_salt(),user_security_answer),user_id = user_id)
                                db.session.add(user_security)
                                db.session.commit()
                                user.user_secure_question_attempt = 3
                                db.session.commit()
                                flash('New security question 2FA successfully added','success')
                                return redirect(url_for('forgot_pass_security_question_verify'))
            else:
                flash('In order to create security question 2FA, you would need to have an account','warning')
                return redirect(url_for('add_user'))
        else:
            return render_template('add_security_question.html',form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/forgot_pass', methods=["GET","POST"])
def forgot_pass():
    try:
        try:
            tel_phone = session["tel_phone"]
        except:
            flash('Forget Password Process Done Incorrectly. Please Do Not Tamper With The URL','error')
            return redirect(url_for('index'))
        form = UserForm()

        password_to_update = Users.query.filter_by(tel_phone=tel_phone).first()
        name = decrypt_data(password_to_update.name)
        username = password_to_update.username
        email = decrypt_data(password_to_update.email)
        pass_user_id = password_to_update.id
        password_in_db = password_to_update.password_hash
        if request.method =="POST":
            passwords= []
            with open('common_password.csv', 'r') as csv_file:
                csv_reader = csv.reader(csv_file)
                for line in csv_reader:
                    passwords.append(line[0])

            new_pass = request.form["password_hash"]
            userpass_pass = UsedPass.query.filter_by(pass_user_id=pass_user_id).all() #get the first 5 passwords VIA user,id in db
            user_used_pass_list = []
            for i in userpass_pass:  #loops through each pass_user_id
                if len(user_used_pass_list) <5:
                    hashed_pass= i.password
                    user_used_pass_list.append(hashed_pass)
                else:
                    break
            for i in range(len(user_used_pass_list)):
                if argon2.verify(new_pass,user_used_pass_list[i]):
                    user_used_pass_list = []
                    flash('Password cannot be a your previous password. Please choose a different password and follow the guidelines.','warning')
                    return redirect(url_for('forgot_pass'))
                else:
                    i +=1
                    if i == len(user_used_pass_list):
                        user_used_pass_list = []

                        stats = PasswordStats(new_pass)
                        checkpolicy = policy.test(new_pass)

                        if ( new_pass.lower() in name.lower() ) or ( new_pass.lower() in name[::-1].lower() ):
                            flash('Password Contains Name. Please Choose A Password That Does Not Contain Any Personal Identifying Information Such As Name, Username, Email Etc. '
                                  'Please Click On Our Password Generator For A Strong Password', 'warning')
                            return redirect(url_for('forgot_pass'))

                        if ( new_pass.lower() in username.lower() ) or ( new_pass.lower() in username[::-1].lower() ):
                            flash('Password Contains Username. Please Choose A Password That Does Not Contain Any Personal Identifying Information Such As Name, Username, Email Etc. '
                                  'Please Click On Our Password Generator For A Strong Password', 'warning')
                            return redirect(url_for('forgot_pass'))

                        if new_pass in passwords:
                            flash('Your Password Has Been Identified as a Common Password. For Your Safety, This Password Cannot Be Used. Please Choose A Stronger Password Or Use Our Password Generator', 'warning')
                            return redirect(url_for('forgot_pass'))

                        if new_pass in email:
                            flash('Password Contains Email. Please Choose A Password That Does Not Contain Any Personal Identifying Information Such As Name, Username, Email Etc. '
                                  'Please Click On Our Password Generator For A Strong Password', 'warning')
                            return redirect(url_for('forgot_pass'))

                        if stats.strength() < 0.5:
                            strength = stats.strength()
                            if stats.strength() <0.33:
                                strength = "Weak"
                            elif stats.strength() <0.5:
                                strength = "Medium"
                            flash(f'Your password is considered as a {strength} Level Password.','warning')
                            return redirect(url_for('forgot_pass'))

                        elif stats.strength() > 0.5 and policy.test(new_pass) != []:
                            unfufilled_requirements_list = checkpolicy
                            flash('You have failed to meet the following requrements','warning')
                            for i in checkpolicy:
                                flash(f'{i}','warning')

                        elif stats.strength() > 0.5 and policy.test(new_pass) == []:
                            password_to_update.password_hash = argon2.hash(request.form["password_hash"])
                            db.session.commit()

                            password_to_update.counter = 5
                            db.session.commit()

                            userpass = UsedPass(password=password_to_update.password_hash, pass_user_id=pass_user_id)
                            db.session.add(userpass)
                            db.session.commit()



                            client.messages.create(
                                body = f"You Have Successfully Changed Your Password At FlaskBlog"
                                       f" If you did not change your password, we would encourage you to log back into your account and change your password to something new. -FlaskBlog",
                                from_= "+14242030414",
                                to= tel_phone
                            )
                            try:
                                id =current_user.id #User logged in
                                logout_user()
                                flash('You will now be signed out. To continue using our services, please sign back in using your new password','success')
                                return redirect(url_for('login'))
                            except: #User NOT logged in
                                flash('Password Has been Reset. Please Log in to your account with your new password','success')
                                return redirect(url_for('index'))

        return render_template('forgot_pass.html',
                               form=form)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
#END OF CHANGE/FORGET USER PASSWORD FUNCTIONS
#----------------------------------------------------------------------------------------------------------------------------------

#UPDATE USER FUNCTION
@app.route('/update/<int:id>', methods=["GET","POST"])
@login_required
def update(id):
    try:
        form= UserForm()
        name_to_update= Users.query.get_or_404(id)
        if request.method == "POST":
            name_to_update.name = request.form['name']
            name_to_update.email = request.form['email']
            name_to_update.dob = request.form['dob']
            name_to_update.username = request.form["username"]
            try:
                db.session.commit()
                flash("User Updated Successfully")
                return render_template('update.html',
                                        form=form,
                                        name_to_update=name_to_update)
            except:
                flash("Error Try Again Later")
                return render_template('update.html',
                                        form=form,
                                        name_to_update=name_to_update)
        else:
            return render_template('update.html',
                                        form=form,
                                        name_to_update=name_to_update,
                                        id=id)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#END OF UPDATE USER FUNCTION
#----------------------------------------------------------------------------------------

#DELETE USER FUNCTION
@app.route('/delete/<int:id>')
@login_required
def delete(id):
    try:
        if id == current_user.id:
            user_to_delete= Users.query.get_or_404(id)
            # post_to_delete = Users.query.filter_by(user=user_to_delete)
            name=None
            form= UserForm()
            try:
                db.session.delete(user_to_delete)
                # db.session.delete(post_to_delete)
                db.session.commit()
                logout_user()
                flash('We Hope You Had An Enjoyable Time Using Our Services','success')
                our_users = Users.query.order_by(Users.date_added)
                return redirect(url_for('index'))
            except:
                flash('Error while deleting, Try Again','error')
                return render_template("dashboard.html",
                                   form=form,
                                   name=name,
                                   our_users=our_users
                                   )
        else:
            flash('Authorised Deletion','error')
            return redirect(url_for('dashboard'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
#END OF DELETE USER FUNCTION
#--------------------------------------------------------------------------------

#LOGOUT FUNCTIONS

@app.route('/logout',methods=["GET","POST"])
@login_required
def logout():
    try:
        logout_user()
        flash('You have been logged out. See You Soon','success')
        return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

@app.route('/session_logout',methods=["GET","POST"])
def session_logout():
    try:
        if AttributeError:
            logout_user()
            flash('If you have logged in, you have been logged out as your session has expired. Please log in again to continue using our services.','error')
            return redirect(url_for('index'))
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
#--------------------------------------------------------------------------------------------------------------------

#DASHBOARD FUNCTION
@app.route('/dashboard',methods=["GET","POST"])
@login_required
def dashboard():
    try:
        form= UserForm()
        id = current_user.id
        try:
            name_to_update= Users.query.get_or_404(id)
            name_to_update.name = decrypt_data(name_to_update.name)

            # name_to_update.dob = decrypt_data(name_to_update.dob)
        except:
            flash('An error has occured while decrypting your data. Please try again.','error')
            logout_user()
            return redirect(url_for('login'))
        try:
            name_to_update.about_author = decrypt_data(name_to_update.about_author)
        except:
            name_to_update.about_author = ''
        if request.method == "POST":
            salt = generate_salt()
            name_to_update.name = encrypt_data(generate_salt(), request.form['name'])

            # name_to_update.dob = request.form['dob']
            name_to_update.username = request.form["username"]
            if request.form["about_author"]:
                name_to_update.about_author = encrypt_data(generate_salt(), request.form["about_author"])
            else:
                name_to_update.about_author = request.form["about_author"]
            #check for profile pic
            #check for profile pic
            if request.files['profile_pic']:
                name_to_update.profile_pic = request.files["profile_pic"]

                #grab image name
                pic_filename = secure_filename(name_to_update.profile_pic.filename)
                #set UUID
                pic_name = str(uuid.uuid1()) + "_" + pic_filename
                #save image
                saver = request.files["profile_pic"]

                #change to str to save in db
                name_to_update.profile_pic = pic_name
                try:
                    db.session.commit()
                    saver.save(os.path.join(app.config['UPLOAD_FOLDER'], pic_name))

                    flash("User Updated Successfully", 'success')
                    return redirect(url_for('dashboard'))
                except:
                    flash("Error Try Again Later", 'error')
                    return render_template('dashboard.html',
                                            form=form,
                                            name_to_update=name_to_update)
            else:
                db.session.commit()
                flash('User Updated Successfully', 'success')
                return redirect(url_for('dashboard'))
        else:
            return render_template('dashboard.html',
                                        form=form,
                                        name_to_update=name_to_update,
                                        id=id)
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))

#END OF DASHBOARD FUNCTION
#-------------------------------------------------------------------------------------------


#ERROR HANDLER FUNCTIONS

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

@app.errorhandler(500)
def page_not_found(e):
    return render_template('500.html'), 500

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('csrf_error.html', reason=e.description), 400

# for testing CSRF
@app.route('/test_csrf', methods=["GET", "POST"])
def test_csrf():
    return str(session.keys())

#END OF ERROR HANDLER FEATURES
#-----------------------------------------------------------------------------------------------------------------

#ADDITIONAL FUNCTIONS
@app.route('/account_safety')
def account_safety():
    try:
        return render_template('account_safety.html')
    except:
        flash('An unexpected error has occurred.','error')
        return redirect(url_for('index'))
#END OF ADDITIONAL FUNCTIONS
#-----------------------------------------------------------------------------------------------------------------

class Posts(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255))
    content = db.Column(db.Text)
    # author = db.Column(db.String(255))
    date_posted = db.Column(db.DateTime, default= date.today())
    slug = db.Column(db.String(255))
    poster_id = db.Column(db.Integer, db.ForeignKey('users.id'))

# 1 user can have many posts FK-PK Relationship
# poster_id is the FK that links to PK of User
# author will now be the username of the user

class UsedPass(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    password = db.Column(db.String())
    pass_user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class UsersSecurityQuestion(db.Model):
    id= db.Column(db.Integer, primary_key=True)
    security_question_id = db.Column(db.String(), unique = True)
    security_answer= db.Column(db.String())
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))

class Users(db.Model, UserMixin):
    id= db.Column(db.Integer, primary_key=True)
    username= db.Column(db.String(20), nullable=False, unique=True , default='')
    name= db.Column(db.String(200), nullable=True)
    email= db.Column(db.String(120), nullable=True, unique=True)
    dob= db.Column(db.String())
    about_author= db.Column(db.Text(500), nullable=True)
    profile_pic = db.Column(db.String(), nullable=True)
    date_added= db.Column(db.DateTime, default=date.today())
    address= db.Column(db.String(), unique=True)
    tel_phone= db.Column(db.String(), unique=True)
    gender=db.Column(db.String())

    #encrypt this
    acc_lockout_counter=db.Column(db.Integer())

    #password hashings stuff
    password_hash= db.Column(db.String())
    git_id = db.Column(db.String(500))
    google_id = db.Column(db.String(500))
    posts = db.relationship('Posts', backref='poster')
    usedpass = db.relationship('UsedPass', backref='userpass')
    user_secure = db.relationship('UsersSecurityQuestion', backref='user_security')
    user_secure_attempt = db.relationship('UsersSecurityQuestion', backref='user_security_attempt')
    user_secure_question_attempt = db.Column(db.Integer())

    counter = db.Column(db.String(300))
    login_count = db.Column(db.Integer())
    logger = db.relationship('UsersLog', backref='logger')

class UsersLog(db.Model):
    id= db.Column(db.Integer, primary_key = True)
    login_counter = db.Column(db.String(300))
    userid = db.Column(db.Integer, db.ForeignKey('users.id'))

    @property
    def password(self):
        raise AttributeError('Password format not comaptable')

    @password.setter
    def password(self, password):
        self.password_hash = argon2.hash(password)

    def verify_password(self, password):
        return argon2.verify(self.password_hash,password)

    def __repr__(self):
        return '<Name %r>' % self.name

if __name__ == "__main__":
    app.run()
