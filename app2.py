from flask import Flask, request, jsonify
import bcrypt
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base, User, Report  

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
    ip = data.get('ip')
    attack_type = data.get('attack_type')

    if not all([ip, attack_type]):
        return jsonify({'message': 'Missing fields'}), 400

    try:
        session = get_db_session()
        
        new_report = Report(
            ip=ip,
            attack_type=attack_type
        )
        
        session.add(new_report)
        session.commit()
        
        return jsonify({
            'message': 'Incident reported successfully',
            'report': {
                'id': new_report.id,
                'ip': new_report.ip,
                'attack_type': new_report.attack_type,
                'reported_at': new_report.reported_at.isoformat() if new_report.reported_at else None
            }
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
            'ip': report.ip,
            'attack_type': report.attack_type,
            'reported_at': report.reported_at.isoformat() if report.reported_at else None
        } for report in reports]
        
        return jsonify({'reports': reports_data})

    except Exception as e:
        return jsonify({'message': str(e)}), 500

    finally:
        session.close()

if __name__ == '__main__':
    app.run(debug=True)