from flask import Flask, request, jsonify
import sqlite3
import hashlib
import json
import os
from hacks.cpake import generate_kyber_keys, encrypt, decrypt
from hacks.params import KYBER_512SK_BYTES, KYBER_SYM_BYTES
from flask_cors import CORS

app = Flask(__name__)
CORS(app)


# Initialize the SQLite database


@app.route('/', methods=['GET'])
def home():
    return jsonify(message="Welcome to the Password Manager App")


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Generate a key pair for the user
    private_key, public_key = generate_kyber_keys(2)
    seed = os.urandom(KYBER_SYM_BYTES)
    seed = bytearray([x & 0xFF for x in seed])

    # Convert password to byte array using UTF-8 encoding
    password_bytes = password.encode('utf-8')
    padded_password = add_padding(password_bytes)

    # Encrypt the password and store it in the database
    cipher = encrypt(padded_password, public_key, seed, 2)
    cipher_bytes = bytearray([x & 0xFF for x in cipher])

    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute('INSERT INTO users (username, encrypted_password, public_key) VALUES (?, ?, ?)',
                   (username, cipher_bytes, json.dumps(public_key)))
    connection.commit()
    connection.close()

    try:
        with open('private_key.txt', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    data[username] = private_key

# Write the updated data back to the file
    with open('private_key.txt', 'w') as f:
        f.write(json.dumps(data, indent=4))

    # You can customize the response message
    return jsonify(message="Registration successful")


def init_db():
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            encrypted_password BLOB,
            public_key BLOB
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            sitename TEXT,
            encrypted_password BLOB,
            type TEXT
        )
    ''')
    connection.commit()
    connection.close()


# Initialize the database when the server starts
init_db()


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    # Check if the username exists in your user database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'SELECT username FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    connection.close()

    if user is None:
        # User not found
        return jsonify({"message": "User not found"}), 404

    # Retrieve the user's private key from the local file
    with open('private_key.txt', 'r') as f:
        private_key = json.loads(f.read())[username]

    # Retrieve the user's encrypted password from the database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'SELECT encrypted_password FROM users WHERE username = ?', (username,))
    encrypted_password = cursor.fetchone()[0]
    connection.close()

    # Decrypt the password
    pwd = decrypt(encrypted_password, private_key, 2)
    original_password = remove_padding(pwd)
    original_password = bytes(original_password).decode('utf-8')

    # Compare the passwords

    if original_password == password:
        print("Login successful")
        return jsonify({"message": "Login successful"})
    else:
        print("Incorrect password")
        return jsonify({"message": "Incorrect password"}), 401


def add_padding(data, block_size=32):
    padding = block_size - (len(data) % block_size)
    if padding != 0:
        data += bytes([padding] * padding)
    return data

# Padding removal function


def remove_padding(data):
    padding = data[-1]
    if padding > 0:
        if all(x == padding for x in data[-padding:]):
            return data[:-padding]
    return data  # No padding or incorrect padding


@app.route('/delete-password', methods=['POST'])
def delete_password():
    data = request.get_json()
    username = data.get('username')
    sitename = data.get('sitename')

    # Delete the password from the database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute('DELETE FROM passwords WHERE username = ? AND sitename = ?',
                   (username, sitename))
    connection.commit()
    connection.close()

    return jsonify(message="Password deleted successfully")


@app.route('/store-password', methods=['POST'])
def store_password():
    print("Storing password")
    data = request.get_json()
    username = data.get('username')
    sitename = data.get('sitename')
    password = data.get('password')
    type = data.get('type')

    # Generate a random seed of the correct length
    seed = os.urandom(KYBER_SYM_BYTES)
    seed = bytearray([x & 0xFF for x in seed])

    # Retrieve the user's public key from the database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'SELECT public_key FROM users WHERE username = ?', (username,))
    public_key = cursor.fetchone()[0]
    connection.close()

    # Convert public key from JSON to bytes
    public_key = json.loads(public_key)

    # Convert password to byte array using UTF-8 encoding
    password_bytes = password.encode('utf-8')
    padded_password = add_padding(password_bytes)

    # Encrypt the password and store it in the database
    cipher = encrypt(padded_password, public_key, seed, 2)
    cipher_bytes = bytearray([x & 0xFF for x in cipher])

    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute('INSERT INTO passwords (username, sitename, encrypted_password, type) VALUES (?, ?, ?,?)',
                   (username, sitename, cipher_bytes, type))
    connection.commit()
    connection.close()

    return jsonify(message="Password stored successfully")


@app.route('/passwords', methods=['GET'])
def get_passwords():
    username = request.args.get('username')
    type = request.args.get('type')

    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'SELECT sitename, encrypted_password FROM passwords WHERE username = ? and type= ?', (username, type))
    encrypted_passwords = cursor.fetchall()
    connection.close()

    # Retrieve the user's private key from the local file
    with open('private_key.txt', 'r') as f:
        private_key = json.loads(f.read())[username]

    passwords = []
    for row in encrypted_passwords:
        sitename = row[0]
        encrypted_password = list(row[1])
        pwd = decrypt(encrypted_password, private_key, 2)
        original_password = remove_padding(pwd)
        passwords.append({"sitename": sitename, "password": bytes(
            original_password).decode('utf-8')})

    return jsonify(message="Passwords retrieved successfully", passwords=passwords)


@app.route('/update-password', methods=['POST'])
def update_password():
    data = request.get_json()
    username = data.get('username')
    sitename = data.get('sitename')

    new_password = data.get('new_password')

    # Generate a random seed of the correct length
    seed = os.urandom(KYBER_SYM_BYTES)
    seed = bytearray([x & 0xFF for x in seed])

    # Retrieve the user's public key from the database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'SELECT public_key FROM users WHERE username = ?', (username,))
    public_key = cursor.fetchone()[0]
    connection.close()

    # Convert public key from JSON to bytes
    public_key = json.loads(public_key)

    # Convert password to byte array using UTF-8 encoding
    password_bytes = new_password.encode('utf-8')
    padded_password = add_padding(password_bytes)

    # Encrypt the password and store it in the database
    cipher = encrypt(padded_password, public_key, seed, 2)
    cipher_bytes = bytearray([x & 0xFF for x in cipher])

    # Update the password in the database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute('UPDATE passwords SET encrypted_password = ? WHERE username = ? AND sitename = ?',
                   (cipher_bytes, username, sitename))
    connection.commit()
    connection.close()

    return jsonify(message="Password updated successfully")


@app.route('/password-sharing', methods=['POST'])
def password_sharing():
    data = request.get_json()
    user2_username = data.get('user2_username')
    user1_username = data.get('user1_username')
    sitename = data.get('sitename')
    password = data.get('password')
    type = data.get('type')

    # Generate a random seed of the correct length
    seed = os.urandom(KYBER_SYM_BYTES)
    seed = bytearray([x & 0xFF for x in seed])

    # Retrieve the user's public key from the database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'SELECT public_key FROM users WHERE username = ?', (user2_username,))
    public_key = cursor.fetchone()[0]
    connection.close()

    # Convert public key from JSON to bytes
    public_key = json.loads(public_key)

    # Convert password to byte array using UTF-8 encoding
    password_bytes = password.encode('utf-8')
    padded_password = add_padding(password_bytes)

    # Encrypt the password and store it in the database
    cipher = encrypt(padded_password, public_key, seed, 2)
    cipher_bytes = bytearray([x & 0xFF for x in cipher])

    # Store the encrypted password in the database with user2's username
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    s = 'Shared ' + type + ' by ' + user1_username + ' :- ' + sitename
    cursor.execute('INSERT INTO passwords (username, sitename, encrypted_password, type) VALUES (?, ?, ?,?)',
                   (user2_username, s, cipher_bytes, type))
    connection.commit()
    connection.close()

    return jsonify(message="Password shared successfully")


if __name__ == '__main__':
    app.run(debug=True)
