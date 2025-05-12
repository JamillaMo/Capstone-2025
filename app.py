from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_mail import Mail, Message
from dotenv import load_dotenv

load_dotenv()  # loads environment variables from .env

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Base, User, Report
import os
import bcrypt

app = Flask(__name__)
app.secret_key = "your_secret_key" #Check

# Database setup
DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(DATABASE_URL, echo=True)
Base.metadata.create_all(engine)
Session = scoped_session(sessionmaker(bind=engine))

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)
#users = {}#

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        db = Session()
        user = db.query(User).filter_by(email=email).first()
        db.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            session['user_email'] = user.email
            session['user_name'] = user.username
            flash("Login successful!", "success")
            return redirect(url_for('dashboard'))
        else:
            flash("Invalid email or password.", "danger")

    return render_template("login.html")


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        db = Session()
        existing_user = db.query(User).filter_by(email=email).first()
        if existing_user:
            flash("Email already exists.", "danger")
            db.close()
            return redirect(url_for('signup'))

        user = User(username=name, email=email, password=hashed.decode())
        db.add(user)
        db.commit()
        db.close()

        flash("Successfully created account!", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/dashboard', endpoint='dashboard')
def showDashboard():
    data = {
        "all_events": 42,  # To be replaced with real data
        "last_result": "Poor",
        "concerns": 3,
    }
    return render_template("dashboard.html", data=data)

@app.route('/reports', endpoint='reports')
def showReports():
    db = Session()
    all_reports = db.query(Report).order_by(Report.reported_at.desc()).all()
    db.close()
    return render_template("reports.html", reports=all_reports)

@app.route('/alerts', endpoint='alerts')
def showAlerts():
    return render_template("alerts.html")

@app.route('/support', endpoint='support', methods=["GET", "POST"])
def showSupport():
    if request.method == "POST":
        name = request.form['name']
        subject = request.form['subject']
        message_body = request.form['message']
        user_email = session.get('user_email', 'noreply@sentriscan.com')

        msg = Message(subject=f"Support Request: {subject}",
                      recipients=["sentriscan@gmail.com"]) # Support inbox
        msg.body = f"From: {name} <{user_email}>\n\n{message_body}"

        # Allows responses go to the user
        msg.reply_to = user_email

        try:
            mail.send(msg)
            flash("Your message has been sent successfully!", "success")
        except Exception as e:
            flash("Failed to send message. Please try again later.", "danger")

        return redirect("/support")
    return render_template("support.html")

@app.route('/settings', endpoint='settings')
def showSettings():
    return render_template("settings.html")

# Run the server
if __name__ == "__main__":
    app.run(debug=True)