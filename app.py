from dotenv import load_dotenv
import os

load_dotenv()  # loads environment variables from .env

from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask_mail import Mail, Message

app = Flask(__name__)
app.secret_key = "your_secret_key"

app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)
users = {}

@app.route('/')
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = users.get(email)

        if user and user['password'] == password:
            session['user_email'] = email
            session['user_name'] = user['name']
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template("login.html")

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # New user
        print(f"New user: {name} ({email})")

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
    return render_template("reports.html")

@app.route('/alerts', endpoint='alerts')
def showAlerts():
    return render_template("alerts.html")

@app.route('/support', endpoint='support', methods=["GET", "POST"])
def showSupport():
    if request.method == "POST":
        name = request.form['name']
        subject = request.form['subject']
        message_body = request.form['message']

        msg = Message(subject=f"Support Request: {subject}",
                      recipients=["destination_email@example.com"])  # Replace with your support inbox
        msg.body = f"From: {name}\n\nMessage:\n{message_body}"

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