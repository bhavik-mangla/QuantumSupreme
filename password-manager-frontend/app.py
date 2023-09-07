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

users = {

    "user1": "password1",
    "user2": "password2",
}

# Initialize the SQLite database


@app.route('/', methods=['GET'])
def home():
    return jsonify(message="Welcome to the Password Manager App")


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    users[username] = password
    print(users)
    # Generate a key pair for the user
    private_key, public_key = generate_kyber_keys(2)
    try:
        with open('private_key.txt', 'r') as f:
            data = json.load(f)
    except FileNotFoundError:
        data = {}

    data[username] = private_key

# Write the updated data back to the file
    with open('private_key.txt', 'w') as f:
        f.write(json.dumps(data, indent=4))

    # Serialize the public_key to JSON
    public_key_json = json.dumps(public_key)

    # Store the serialized public_key and username in the database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'INSERT INTO users (username, public_key) VALUES (?, ?)', (username, public_key_json))
    connection.commit()
    connection.close()

    # Retrieve the user's public key from the database
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'SELECT public_key FROM users WHERE username = ?', (username,))
    public_key = cursor.fetchone()[0]
    connection.close()

    # You can customize the response message
    return jsonify(message="Registration successful")


def init_db():
    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            public_key BLOB
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS passwords (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            sitename TEXT,
            encrypted_password BLOB
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
    if username in users:
        # Check if the provided password matches the stored password
        if users[username] == password:
            # Authentication successful
            print("Login successful")
            return jsonify({"message": "Login successful"})
        else:
            # Incorrect password
            return jsonify({"message": "Incorrect password"}), 401
    else:
        # User not found
        return jsonify({"message": "User not found"}), 404


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


@app.route('/store-password', methods=['POST'])
def store_password():
    print("Storing password")
    data = request.get_json()
    username = data.get('username')
    sitename = data.get('sitename')
    password = data.get('password')

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
    cursor.execute('INSERT INTO passwords (username, sitename, encrypted_password) VALUES (?, ?, ?)',
                   (username, sitename, cipher_bytes))
    connection.commit()
    connection.close()

    return jsonify(message="Password stored successfully")


@app.route('/passwords', methods=['GET'])
def get_passwords():
    username = request.args.get('username')

    connection = sqlite3.connect('password_manager.db')
    cursor = connection.cursor()
    cursor.execute(
        'SELECT sitename, encrypted_password FROM passwords WHERE username = ?', (username,))
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


if __name__ == '__main__':
    app.run(debug=True)
