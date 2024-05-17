import os
import sqlite3

from werkzeug.security import generate_password_hash

# Connect to SQLite database (it will be created if it doesn't exist)
conn = sqlite3.connect("users.db")
c = conn.cursor()

# Create table
c.execute(
    """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
"""
)

# Insert an example user (username: from env, password: from env)
admin_username = os.getenv("ADMIN_USERNAME", "admin")
admin_password = generate_password_hash(os.getenv("ADMIN_PASSWORD", "password123"))

c.execute(
    """
INSERT OR IGNORE INTO users (username, password) VALUES (?, ?)
""",
    (admin_username, admin_password),
)

# Save (commit) the changes and close the connection
conn.commit()
conn.close()

print(f"Database setup complete with a default user ({admin_username}).")
