from flask import Flask, request, jsonify, render_template_string
import psycopg2
import os
import logging
import hashlib
import jwt
from datetime import datetime, timedelta

# INTENTIONAL VULNERABILITIES FOR DEMONSTRATION PURPOSES
# This application contains security flaws that will be detected by security tools

app = Flask(__name__)

# VULNERABILITY: Hardcoded secret key
app.secret_key = "supersecretkey123"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration with VULNERABLE practices
DB_CONFIG = {
    'host': os.getenv('DB_HOST', 'postgres'),
    'database': os.getenv('DB_NAME', 'demo'),
    'user': os.getenv('DB_USER', 'user'),
    'password': os.getenv('DB_PASSWORD', 'password'),  # VULNERABLE: Plain text password
    'port': os.getenv('DB_PORT', '5432')
}

# VULNERABILITY: SQL injection prone function
def get_user_data(user_id):
    """VULNERABLE: Direct string formatting allows SQL injection"""
    connection = None
    try:
        connection = psycopg2.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        # DANGEROUS: Direct string formatting - SQL injection risk
        query = f"SELECT * FROM users WHERE id = {user_id}"
        cursor.execute(query)
        
        result = cursor.fetchone()
        return result
    except Exception as e:
        logger.error(f"Database error: {e}")
        return None
    finally:
        if connection:
            connection.close()

# VULNERABILITY: Weak authentication
def authenticate_user(username, password):
    """VULNERABLE: Weak password hashing"""
    connection = None
    try:
        connection = psycopg2.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        # VULNERABLE: MD5 hashing (deprecated)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        # VULNERABLE: SQL injection possible
        query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{hashed_password}'"
        cursor.execute(query)
        
        user = cursor.fetchone()
        return user is not None
    except Exception as e:
        logger.error(f"Authentication error: {e}")
        return False
    finally:
        if connection:
            connection.close()

# VULNERABILITY: JWT with weak secret
def generate_token(username):
    """VULNERABLE: Weak JWT secret"""
    payload = {
        'username': username,
        'exp': datetime.utcnow() + timedelta(hours=24),
        'admin': True  # VULNERABLE: All users get admin privileges
    }
    # VULNERABLE: Weak secret
    token = jwt.encode(payload, "weak_secret", algorithm="HS256")
    return token

@app.route('/')
def home():
    """Home page with basic information"""
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Sentinel Demo Application</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .header { background-color: #f4f4f4; padding: 20px; border-radius: 5px; }
            .vulnerability { background-color: #ffe6e6; padding: 10px; margin: 10px 0; border-left: 4px solid #ff0000; }
            .endpoint { background-color: #e6f3ff; padding: 10px; margin: 10px 0; border-left: 4px solid #0066cc; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ Sentinel Security Demo Application</h1>
            <p>This application contains intentional security vulnerabilities for demonstration purposes.</p>
        </div>
        
        <div class="vulnerability">
            <h3>⚠️ Known Vulnerabilities (for demo purposes):</h3>
            <ul>
                <li>SQL Injection in user lookup</li>
                <li>Hardcoded secrets and passwords</li>
                <li>Weak password hashing (MD5)</li>
                <li>Insufficient access controls</li>
                <li>Information disclosure in error messages</li>
            </ul>
        </div>
        
        <div class="endpoint">
            <h3>Available Endpoints:</h3>
            <ul>
                <li><strong>GET /</strong> - This home page</li>
                <li><strong>GET /health</strong> - Health check</li>
                <li><strong>GET /user/&lt;id&gt;</strong> - Get user data (vulnerable to SQL injection)</li>
                <li><strong>POST /login</strong> - User authentication</li>
                <li><strong>GET /admin</strong> - Admin panel (insufficient access control)</li>
                <li><strong>GET /config</strong> - Configuration data (information disclosure)</li>
            </ul>
        </div>
        
        <h3>Security Testing:</h3>
        <p>Try these SQL injection payloads on <code>/user/&lt;id&gt;</code>:</p>
        <ul>
            <li><code>1 OR 1=1</code></li>
            <li><code>1; DROP TABLE users; --</code></li>
            <li><code>1 UNION SELECT version(), current_user, now()</code></li>
        </ul>
    </body>
    </html>
    """
    return render_template_string(html_template)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': '1.0.0'
    })

@app.route('/user/<user_id>')
def get_user(user_id):
    """VULNERABLE: SQL injection endpoint"""
    try:
        user_data = get_user_data(user_id)
        if user_data:
            return jsonify({
                'user_id': user_data[0],
                'username': user_data[1],
                'email': user_data[2],
                'created_at': user_data[3].isoformat() if user_data[3] else None
            })
        else:
            # VULNERABILITY: Information disclosure in error message
            return jsonify({'error': f'User {user_id} not found in database'}), 404
    except Exception as e:
        # VULNERABILITY: Detailed error messages
        return jsonify({'error': f'Database error: {str(e)}'}), 500

@app.route('/login', methods=['POST'])
def login():
    """VULNERABLE: Authentication endpoint"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        if authenticate_user(username, password):
            token = generate_token(username)
            return jsonify({
                'message': 'Login successful',
                'token': token,
                'admin': True  # VULNERABLE: All users are admin
            })
        else:
            return jsonify({'error': 'Invalid credentials'}), 401
    except Exception as e:
        return jsonify({'error': f'Login error: {str(e)}'}), 500

@app.route('/admin')
def admin_panel():
    """VULNERABLE: No access control"""
    # VULNERABILITY: No authentication check
    return jsonify({
        'message': 'Welcome to admin panel',
        'users_count': 100,
        'system_info': {
            'os': os.name,
            'python_version': '3.9',
            'database_host': DB_CONFIG['host']  # VULNERABILITY: Information disclosure
        },
        # VULNERABILITY: Exposing sensitive configuration
        'database_config': DB_CONFIG
    })

@app.route('/config')
def get_config():
    """VULNERABLE: Configuration disclosure"""
    # VULNERABILITY: Exposing all environment variables
    return jsonify({
        'environment_variables': dict(os.environ),
        'database_config': DB_CONFIG,
        'secret_key': app.secret_key,  # VULNERABILITY: Exposing secret key
        'debug_mode': app.debug
    })

@app.route('/file')
def read_file():
    """VULNERABLE: Path traversal"""
    filename = request.args.get('filename', 'default.txt')
    try:
        # VULNERABILITY: No path validation - path traversal possible
        with open(filename, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/command')
def execute_command():
    """VULNERABLE: Command injection"""
    cmd = request.args.get('cmd', 'ls')
    try:
        # VULNERABILITY: Direct command execution
        import subprocess
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        return jsonify({
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    """VULNERABLE: Information disclosure in 404 errors"""
    return jsonify({
        'error': '404 Not Found',
        'path': request.path,
        'method': request.method,
        'headers': dict(request.headers),  # VULNERABILITY: Exposing all headers
        'remote_addr': request.remote_addr
    }), 404

@app.errorhandler(500)
def internal_error(error):
    """VULNERABLE: Detailed error information"""
    import traceback
    return jsonify({
        'error': '500 Internal Server Error',
        'traceback': traceback.format_exc(),  # VULNERABILITY: Exposing stack trace
        'timestamp': datetime.utcnow().isoformat()
    }), 500

if __name__ == '__main__':
    # Initialize database (create table if not exists)
    try:
        connection = psycopg2.connect(**DB_CONFIG)
        cursor = connection.cursor()
        
        # Create users table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password VARCHAR(32) NOT NULL,
                email VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Insert demo users with weak passwords
        demo_users = [
            ('admin', hashlib.md5('admin123'.encode()).hexdigest(), 'admin@example.com'),
            ('user1', hashlib.md5('password'.encode()).hexdigest(), 'user1@example.com'),
            ('test', hashlib.md5('test123'.encode()).hexdigest(), 'test@example.com')
        ]
        
        for username, password_hash, email in demo_users:
            cursor.execute("""
                INSERT INTO users (username, password, email) 
                VALUES (%s, %s, %s) 
                ON CONFLICT (username) DO NOTHING
            """, (username, password_hash, email))
        
        connection.commit()
        logger.info("Database initialized successfully")
        
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
    finally:
        if 'connection' in locals():
            connection.close()
    
    # VULNERABILITY: Debug mode enabled in production
    app.run(host='0.0.0.0', port=5000, debug=True)