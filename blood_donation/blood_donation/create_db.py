# create_db.py
import sqlite3

conn = sqlite3.connect('database.db')
c = conn.cursor()

c.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
''')

# Add to create_db.py
conn.execute('''
CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
''')

# Insert default admin (username: admin, password: admin123)
from flask_bcrypt import Bcrypt
bcrypt = Bcrypt()

hashed = bcrypt.generate_password_hash('admin123').decode('utf-8')
conn.execute('INSERT OR IGNORE INTO admins (username, password) VALUES (?, ?)', ('admin', hashed))

conn.execute('''
CREATE TABLE IF NOT EXISTS donors (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    blood_group TEXT,
    phone TEXT,
    city TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
)
''')

conn.execute('''
CREATE TABLE IF NOT EXISTS blood_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER,
    blood_group TEXT,
    phone TEXT,
    city TEXT,
    reason TEXT,
    FOREIGN KEY(requester_id) REFERENCES users(id)
)
''')


conn.commit()
conn.close()

print("Database initialized.")
