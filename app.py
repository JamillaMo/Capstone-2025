from flask import Flask, render_template, request, redirect, flash, session, url_for
from flask import jsonify
from flask_mail import Mail, Message
from dotenv import load_dotenv

load_dotenv()  # loads environment variables from .env

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from models import Base, User, Report
from security_scan import launch_ids, perform_reconnaissance, perform_network_scan, comprehensive_scan
import os
import bcrypt

app = Flask(__name__)
app.secret_key = "lmnopqrstuvwxyz"  # Replace with a strong secret key

# Database setup
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///database.db')  # Default to SQLite if not set
engine = create_engine(DATABASE_URL, echo=True)
Base.metadata.create_all(engine)
Session = scoped_session(sessionmaker(bind=engine))

# Flask-Mail setup
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT'))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS') == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

mail = Mail(app)

#Get database session
def get_db_session():
    return Session()


# API routes
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

@app.route('/input', methods=['GET', 'POST'])
def input_data():
    if request.method == 'POST':
        ip = request.form['ip']

        # Validate the IP address (optional)
        if not ip:
            flash("IP address is required.", "danger")
            return redirect('/input')

        # Save the IP address in the session
        session['scan_ip'] = ip
        flash(f"IP address '{ip}' saved successfully!", "success")

        # Redirect to the dashboard or another page
        return redirect(url_for('dashboard'))

    return render_template('input.html')


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

@app.route('/report', methods=['POST'])
def add_report():
    data = request.json
    
    required_fields = ['domain', 'ip', 'high', 'critical']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields'}), 400

    try:
        session = get_db_session()
        
        new_report = Report(
            domain=data['domain'],
            ip=data['ip'],
            high=data['high'],
            critical=data['critical'],
            os=data.get('os'),
            whois=data.get('whois'),
            nmap_info=data.get('Nmap_info'),
            num_vulnerabilities=data.get('No. of Vulnerabilities', 0),
            vulnerabilities=data.get('Vulnerabilities')
        )
        
        session.add(new_report)
        session.commit()
        
        return jsonify({
            'message': 'Report created successfully',
            'report_id': new_report.id
        }), 201

    except Exception as e:
        session.rollback()
        return jsonify({'message': str(e)}), 500

    finally:
        session.close()

# Route: Get all incident reports
@app.route('/reports', methods=['GET'])
def get_reports():
    try:
        session = get_db_session()
        reports = session.query(Report).order_by(Report.reported_at.desc()).all()
        
        reports_data = [{
            'id': report.id,
            'domain': report.domain,
            'ip': report.ip,
            'high': report.high,
            'critical': report.critical,
            'os': report.os,
            'whois': report.whois,
            'Nmap_info': report.nmap_info,
            'No. of Vulnerabilities': report.num_vulnerabilities,
            'Vulnerabilities': report.vulnerabilities,
            'reported_at': report.reported_at.isoformat() if report.reported_at else None
        } for report in reports]
        
        return jsonify({'reports': reports_data})

    except Exception as e:
        return jsonify({'message': str(e)}), 500

    finally:
        session.close()



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



# Buttons on the Dashboard

@app.route('/launchIDS', methods=['POST'])
def launchIDS():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({'message': 'IP address is required', 'status': 'error'}), 400

    # Call the respective scan function
    result = launch_ids(ip)
    return jsonify({'message': f'IDS launched successfully for IP: {ip}', 'result': result, 'status': 'success'})


@app.route('/conductRecon', methods=['POST'])
def conductRecon():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({'message': 'IP address is required', 'status': 'error'}), 400

    # Call the respective scan function
    result = perform_reconnaissance(ip)
    return jsonify({'message': f'Reconnaissance executed successfully for IP: {ip}', 'result': result, 'status': 'success'})


@app.route('/runNetScan', methods=['POST'])
def runNetScan():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({'message': 'IP address is required', 'status': 'error'}), 400

    # Call the respective scan function
    result = perform_network_scan(ip)
    return jsonify({'message': f'Network scan completed successfully for IP: {ip}', 'result': result, 'status': 'success'})


@app.route('/runCompScan', methods=['POST'])
def runCompScan():
    data = request.json
    ip = data.get('ip')
    if not ip:
        return jsonify({'message': 'IP address is required', 'status': 'error'}), 400

    # Call the respective scan function
    result = comprehensive_scan(ip)
    return jsonify({'message': f'Comprehensive scan completed successfully for IP: {ip}', 'result': result, 'status': 'success'})



# Run the server
if __name__ == "__main__":
    app.run(debug=True)