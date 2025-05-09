# pip install mysql-connector-python

import mysql.connector

# Database connection parameters
host = 'localhost'
user = 'root'
password = 'your_password'
database = 'my_database'

# Connect to MySQL server (without selecting DB yet)
conn = mysql.connector.connect(
    host=host,
    user=user,
    password=password
)
cursor = conn.cursor()

# Create database
cursor.execute(f"CREATE DATABASE IF NOT EXISTS {database}")
print(f"Database '{database}' created or already exists.")

# Connect to the newly created database
conn.database = database

# Create users table
cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

print("Users table created successfully.")


cursor.execute('''
CREATE TABLE IF NOT EXISTS reports (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip VARCHAR(45) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    reported_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
''')

print("Reropts table created successfully.")

# Clean up
cursor.close()
conn.close()

pip install flask mysql-connector-python bcrypt

from flask import Flask, request, jsonify
import mysql.connector
import bcrypt

app = Flask(__name__)

# Database connection settings
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': 'your_password',
    'database': 'my_database'
}

# Helper: Connect to database
def get_db_connection():
    return mysql.connector.connect(**db_config)

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
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO users (username, email, password)
            VALUES (%s, %s, %s)
        ''', (username, email, hashed_password))

        conn.commit()
        return jsonify({'message': 'User registered successfully'}), 201

    except mysql.connector.Error as err:
        return jsonify({'message': str(err)}), 500

    finally:
        cursor.close()
        conn.close()

# Route: Login user
@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    if not all([email, password]):
        return jsonify({'message': 'Missing fields'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute('SELECT * FROM users WHERE email = %s', (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
            return jsonify({'message': 'Login successful', 'user': {'id': user['id'], 'username': user['username'], 'email': user['email']}})
        else:
            return jsonify({'message': 'Invalid email or password'}), 401

    except mysql.connector.Error as err:
        return jsonify({'message': str(err)}), 500

    finally:
        cursor.close()
        conn.close

# Route: Add new incident report
@app.route('/report', methods=['POST'])
def add_report():
    data = request.json
    ip = data.get('ip')
    attack_type = data.get('attack_type')

    if not all([ip, attack_type]):
        return jsonify({'message': 'Missing fields'}), 400

    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute('''
            INSERT INTO report (ip, attack_type)
            VALUES (%s, %s)
        ''', (ip, attack_type))

        conn.commit()
        return jsonify({'message': 'Incident reported successfully'}), 201

    except mysql.connector.Error as err:
        return jsonify({'message': str(err)}), 500

    finally:
        cursor.close()
        conn.close()

# Route: Get all incident reports
@app.route('/reports', methods=['GET'])
def get_reports():
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)

        cursor.execute('SELECT * FROM report ORDER BY reported_at DESC')
        reports = cursor.fetchall()

        return jsonify({'reports': reports})

    except mysql.connector.Error as err:
        return jsonify({'message': str(err)}), 500

    finally:
        cursor.close()
        conn.close()


# if __name__ == '__main__':
#     app.run(debug=True)
