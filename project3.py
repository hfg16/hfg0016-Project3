#creator: hfg0016

import os
import sqlite3
from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from passlib.hash import argon2
from functools import wraps
import time
import uuid

app = Flask(__name__)

# Database initialization
db_path = "totally_not_my_privateKeys.db"

# Ensure the database file exists
if not os.path.exists(db_path):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            email TEXT UNIQUE,
            date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
    ''')

    # Create auth_logs table
    c.execute('''
        CREATE TABLE IF NOT EXISTS auth_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_ip TEXT NOT NULL,
            request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_id INTEGER,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    conn.commit()
    conn.close()

# Retrieve the encryption key from the environment variable
encryption_key = os.getenv("NOT_MY_KEY", "default_key")


'''def encrypt(data):
    # Implement AES encryption logic using encryption_key
    # This implementation is simplified for demonstration purposes
    # In a production scenario, use a proper encryption library
    return data


def decrypt(data):
    # Implement AES decryption logic using encryption_key
    # This implementation is simplified for demonstration purposes
    # In a production scenario, use a proper encryption library
    return data'''

# Encrypt private keys using AES
def encrypt_private_key(private_key):
    cipher = AES.new(encryption_key.encode('utf-8'), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(private_key.encode('utf-8'))
    return cipher.nonce + tag + ciphertext

def decrypt_private_key(encrypted_data):
    nonce = encrypted_data[:16]
    tag = encrypted_data[16:32]
    ciphertext = encrypted_data[32:]
    cipher = AES.new(encryption_key.encode('utf-8'), AES.MODE_EAX, nonce=nonce)
    private_key = cipher.decrypt_and_verify(ciphertext, tag)
    return private_key.decode('utf-8')


def rate_limit(limit=10, per=1):
    """
    Decorator function for rate limiting.
    """
    def decorator(func):
        request_history = []

        @wraps(func)
        def wrapper(*args, **kwargs):
            current_time = time.time()
            request_history.append(current_time)

            # Remove requests outside the time window
            request_history = [t for t in request_history if current_time - t <= per]

            if len(request_history) > limit:
                return jsonify({"error": "Too Many Requests"}), 429

            result = func(*args, **kwargs)
            return result

        return wrapper

    return decorator


@app.route('/register', methods=['POST'])
def register_user():
    data = request.get_json()

    # Generate a secure password using UUIDv4
    password = str(uuid.uuid4())

    # Hash the password using Argon2
    password_hash = argon2.hash(password)

    # Encrypt the password before storing it in the database
    encrypted_password = encrypt_private_key(password_hash)

    # Store user details in the database
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('''
        INSERT INTO users (username, password_hash, email) 
        VALUES (?, ?, ?)
    ''', (data['username'], encrypted_password, data['email']))
    user_id = c.lastrowid
    conn.commit()
    conn.close()

    return jsonify({"password": password}), 200


@app.route('/auth', methods=['POST'])
@rate_limit(limit=10, per=1)
def authenticate_user():
    data = request.get_json()

    # Decrypt the password before comparing with the stored hash
    decrypted_password = decrypt_private_key(data['password'])

    # Retrieve user details from the database
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE username = ?', (data['username'],))
    user = c.fetchone()
    conn.close()

    if user and argon2.verify(decrypted_password, user[2]):
        # Log the authentication request
        request_ip = request.remote_addr
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute('''
            INSERT INTO auth_logs (request_ip, user_id) 
            VALUES (?, ?)
        ''', (request_ip, user[0]))
        conn.commit()
        conn.close()

        return jsonify({"message": "Authentication successful"}), 200
    else:
        return jsonify({"error": "Invalid credentials"}), 401


if __name__ == '__main__':
    app.run(debug=True, port=8080)
