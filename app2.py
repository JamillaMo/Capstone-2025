from flask import Flask, request, jsonify
import bcrypt
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Alert, Base, User, Report  

app = Flask(__name__)

# Database configuration
DATABASE_URI = "mysql+mysqlconnector://root:your_password@localhost/my_database"
engine = create_engine(DATABASE_URI)
Base.metadata.create_all(engine) 
Session = sessionmaker(bind=engine)

#Get database session
def get_db_session():
    return Session()

# Route: Register user
@app.route('/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')

    if not all([username, email, password]):
        return jsonify({'message': 'Missing fields'}), 400

    # Hash password
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    try:
        session = get_db_session()
        
        # Check if username or email already exists
        if session.query(User).filter((User.username == username) | (User.email == email)).first():
            return jsonify({'message': 'Username or email already exists'}), 400

        new_user = User(
            username=username,
            email=email,
            password=hashed_password.decode('utf-8') 
        )
        
        session.add(new_user)
        session.commit()
        
        return jsonify({
            'message': 'User registered successfully',
            'user': {
                'id': new_user.id,
                'username': new_user.username,
                'email': new_user.email
            }
        }), 201

    except Exception as e:
        session.rollback()
        return jsonify({'message': str(e)}), 500

    finally:
        session.close()

# Route: Login user
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'message': 'Missing fields'}), 400

    try:
        session = get_db_session()
        user = session.query(User).filter(User.email == email).first()

        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            return jsonify({
                'message': 'Login successful',
                'user': {
                    'id': user.id,
                    'username': user.username,
                    'email': user.email
                }
            })
        else:
            return jsonify({'message': 'Invalid email or password'}), 401

    except Exception as e:
        return jsonify({'message': str(e)}), 500

    finally:
        session.close()

# Route: Add new incident report
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


# Route: Create new alert
@app.route('/alerts', methods=['POST'])
def create_alert():
    data = request.json
    alert_info = data.get('alert_info')

    if not alert_info:
        return jsonify({'message': 'Alert information is required'}), 400

    try:
        session = get_db_session()
        
        new_alert = Alert(
            alert_info=alert_info
        )
        
        session.add(new_alert)
        session.commit()
        
        return jsonify({
            'message': 'Alert created successfully',
            'alert': {
                'id': new_alert.id,
                'alert_info': new_alert.alert_info,
                'created_at': new_alert.created_at.isoformat() if new_alert.created_at else None
            }
        }), 201

    except Exception as e:
        session.rollback()
        return jsonify({'message': str(e)}), 500

    finally:
        session.close()

# Route: Get all alerts
@app.route('/alerts', methods=['GET'])
def get_alerts():
    try:
        session = get_db_session()
        alerts = session.query(Alert).order_by(Alert.created_at.desc()).all()
        
        alerts_data = [{
            'id': alert.id,
            'alert_info': alert.alert_info,
            'created_at': alert.created_at.isoformat() if alert.created_at else None
        } for alert in alerts]
        
        return jsonify({'alerts': alerts_data})

    except Exception as e:
        return jsonify({'message': str(e)}), 500

    finally:
        session.close()

# Route: Get single alert by ID
@app.route('/alerts/<int:alert_id>', methods=['GET'])
def get_alert(alert_id):
    try:
        session = get_db_session()
        alert = session.query(Alert).filter(Alert.id == alert_id).first()
        
        if not alert:
            return jsonify({'message': 'Alert not found'}), 404
            
        return jsonify({
            'id': alert.id,
            'alert_info': alert.alert_info,
            'created_at': alert.created_at.isoformat() if alert.created_at else None
        })

    except Exception as e:
        return jsonify({'message': str(e)}), 500

    finally:
        session.close()

if __name__ == '__main__':
    app.run(debug=True)
