#!/usr/bin/env python3
"""
Deliberately Vulnerable Web Application for Testing Xploit
WARNING: DO NOT DEPLOY TO PRODUCTION - INTENTIONALLY INSECURE
"""

from flask import Flask, request, render_template_string
import sqlite3
import os

app = Flask(__name__)

# Create vulnerable SQLite database
def init_db():
    conn = sqlite3.connect('/tmp/vuln.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'secret123')")
    c.execute("INSERT INTO users VALUES (2, 'user', 'pass456')")
    conn.commit()
    conn.close()

init_db()

@app.route('/')
def index():
    return '''
    <html><body>
        <h1>Vulnerable Test App</h1>
        <a href="/sqli?id=1">SQL Injection Test</a><br>
        <a href="/xss?q=test">XSS Test</a><br>
        <form action="/search" method="GET">
            <input name="query" placeholder="Search">
            <button>Search</button>
        </form>
    </body></html>
    '''

# Vulnerable to SQL Injection
@app.route('/sqli')
def sqli():
    user_id = request.args.get('id', '1')
    conn = sqlite3.connect('/tmp/vuln.db')
    c = conn.cursor()

    # INTENTIONALLY VULNERABLE - NO PARAMETERIZATION
    try:
        query = f"SELECT * FROM users WHERE id = {user_id}"
        c.execute(query)
        result = c.fetchall()
        return f"<html><body><h1>User Info</h1><pre>Query: {query}\nResult: {result}</pre></body></html>"
    except Exception as e:
        # Leak database errors (error-based SQLi detection)
        return f"<html><body><h1>Database Error</h1><pre>{str(e)}</pre></body></html>"
    finally:
        conn.close()

# Vulnerable to XSS
@app.route('/xss')
def xss():
    user_input = request.args.get('q', '')
    # INTENTIONALLY VULNERABLE - NO ESCAPING
    return f'''
    <html><body>
        <h1>Search Results</h1>
        <p>You searched for: {user_input}</p>
        <p>Results: No items found</p>
    </body></html>
    '''

# Vulnerable to XSS via form
@app.route('/search')
def search():
    query = request.args.get('query', '')
    # INTENTIONALLY VULNERABLE
    return f'''
    <html><body>
        <h1>Results for: {query}</h1>
        <form action="/search" method="GET">
            <input name="query" value="{query}">
            <button>Search Again</button>
        </form>
    </body></html>
    '''

# Vulnerable to Directory Traversal
@app.route('/file')
def file_read():
    filepath = request.args.get('path', 'test.txt')
    try:
        # INTENTIONALLY VULNERABLE
        with open(filepath, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == '__main__':
    print("Starting vulnerable test app on http://127.0.0.1:5000")
    print("WARNING: This app is INTENTIONALLY INSECURE for testing only!")
    app.run(host='127.0.0.1', port=5000, debug=False)
