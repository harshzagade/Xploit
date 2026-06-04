#!/usr/bin/env python3
"""
Deliberately Vulnerable Web Application for Testing Xploit
WARNING: DO NOT DEPLOY TO PRODUCTION - INTENTIONALLY INSECURE
"""

from flask import Flask, request, render_template_string, session, redirect
import sqlite3
import os

app = Flask(__name__)
app.secret_key = 'insecure_secret'

# Create vulnerable SQLite database
def init_db():
    conn = sqlite3.connect('/tmp/vuln.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT)''')
    c.execute("DELETE FROM users")
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin')")
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
        <a href="/login">Login Page</a><br>
        <form action="/search" method="GET">
            <input name="query" placeholder="Search">
            <button>Search</button>
        </form>
    </body></html>
    '''

# Vulnerable login page (accepts admin/admin - default credentials)
@app.route('/login', methods=['GET', 'POST'])
def login():
    error = ''
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')

        conn = sqlite3.connect('/tmp/vuln.db')
        c = conn.cursor()
        try:
            # Also vulnerable to SQLi
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            c.execute(query)
            user = c.fetchone()
        except Exception as e:
            user = None
        finally:
            conn.close()

        if user:
            session['user'] = username
            return redirect('/dashboard')
        else:
            error = 'Invalid credentials'

    return f'''
    <html><body>
        <h1>Login</h1>
        <p style="color:red">{error}</p>
        <form action="/login" method="POST">
            <label>Username: <input name="username" type="text"></label><br>
            <label>Password: <input name="password" type="password"></label><br>
            <button type="submit">Login</button>
        </form>
    </body></html>
    '''

@app.route('/dashboard')
def dashboard():
    user = session.get('user', 'Guest')
    return f'''
    <html><body>
        <h1>Welcome {user}!</h1>
        <p>You are logged in.</p>
        <a href="/logout">Logout</a>
    </body></html>
    '''

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/login')

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
