import os
from flask import Flask, request, jsonify, make_response
from flask_mysqldb import MySQL
import jwt
import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp
import qrcode
from io import BytesIO
import base64
from functools import wraps

app = Flask(__name__)

# MySQL Configuration (using XAMPP defaults)
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''  # Default XAMPP password is empty
app.config['MYSQL_DB'] = 'flask_auth_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = 'your-secret-key-here'  # Change this in production!

mysql = MySQL(app)

# JWT token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = data['username']
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
            
        return f(current_user, *args, **kwargs)
        
    return decorated

# User Registration
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400
    
    # Generate a secret for 2FA
    secret = pyotp.random_base32()
    
    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    cur = mysql.connection.cursor()
    
    try:
        cur.execute(
            "INSERT INTO Users (username, password, twofa_secret) VALUES (%s, %s, %s)",
            (username, hashed_password, secret)
        )
        mysql.connection.commit()
    except Exception as e:
        return jsonify({'message': 'Username already exists!'}), 400
    finally:
        cur.close()
    
    return jsonify({
        'message': 'User registered successfully!',
        'secret': secret  # In production, don't return the secret to the client
    }), 201

# Get QR Code for Google Authenticator
@app.route('/get-qr', methods=['POST'])
def get_qr():
    data = request.get_json()
    
    username = data.get('username')
    password = data.get('password')  # New: Require password
    
    if not username or not password:
        return jsonify({'message': 'Username and password are required!'}), 400
    
    cur = mysql.connection.cursor()
    
    try:
        # First verify credentials
        cur.execute("SELECT password, twofa_secret FROM Users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if not user:
            return jsonify({'message': 'User not found!'}), 404
            
        if not check_password_hash(user['password'], password):
            return jsonify({'message': 'Invalid credentials!'}), 401
        
        secret = user['twofa_secret']
        
        # Create QR code only after successful authentication
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name="Flask 2FA App"
        )
        
        img = qrcode.make(totp_uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        img_str = base64.b64encode(buffered.getvalue()).decode()
        
        return jsonify({
            'qr_code': f"data:image/png;base64,{img_str}",
            'secret': secret
        })
        
    finally:
        cur.close()

# Login with 2FA
@app.route('/login', methods=['POST'])
def login():
    auth = request.get_json()
    
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Username and password are required!'}), 401
    
    username = auth.get('username')
    password = auth.get('password')
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM Users WHERE username = %s", (username,))
    user = cur.fetchone()
    cur.close()
    
    if not user:
        return jsonify({'message': 'User not found!'}), 404
    
    if check_password_hash(user['password'], password):
        # Password is correct, now check for 2FA code
        if 'twofa_code' not in auth:
            return jsonify({'message': '2FA code required!'}), 202  # 202 Accepted but needs 2FA
        
        # Verify 2FA code
        secret = user['twofa_secret']
        totp = pyotp.TOTP(secret)
        
        if not totp.verify(auth.get('twofa_code')):
            return jsonify({'message': 'Invalid 2FA code!'}), 401
        
        # Generate JWT token
        token = jwt.encode({
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=10)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({
            'message': 'Login successful!',
            'token': token
        })
    
    return jsonify({'message': 'Invalid credentials!'}), 401

# CRUD Operations for Products

# Create Product
@app.route('/products', methods=['POST'])
@token_required
def create_product(current_user):
    data = request.get_json()
    
    required_fields = ['name', 'description', 'price', 'quantity']
    if not all(field in data for field in required_fields):
        return jsonify({'message': 'Missing required fields!'}), 400
    
    cur = mysql.connection.cursor()
    cur.execute(
        "INSERT INTO Products (name, description, price, quantity) VALUES (%s, %s, %s, %s)",
        (data['name'], data['description'], data['price'], data['quantity'])
    )
    mysql.connection.commit()
    product_id = cur.lastrowid
    cur.close()
    
    return jsonify({
        'message': 'Product created successfully!',
        'product_id': product_id
    }), 201

# Get All Products
@app.route('/products', methods=['GET'])
@token_required
def get_products(current_user):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM Products")
    products = cur.fetchall()
    cur.close()
    
    return jsonify({'products': products})

# Get Single Product
@app.route('/products/<int:product_id>', methods=['GET'])
@token_required
def get_product(current_user, product_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM Products WHERE id = %s", (product_id,))
    product = cur.fetchone()
    cur.close()
    
    if not product:
        return jsonify({'message': 'Product not found!'}), 404
    
    return jsonify({'product': product})

# Update Product
@app.route('/products/<int:product_id>', methods=['PUT'])
@token_required
def update_product(current_user, product_id):
    data = request.get_json()
    
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM Products WHERE id = %s", (product_id,))
    product = cur.fetchone()
    
    if not product:
        cur.close()
        return jsonify({'message': 'Product not found!'}), 404
    
    # Update only provided fields
    name = data.get('name', product['name'])
    description = data.get('description', product['description'])
    price = data.get('price', product['price'])
    quantity = data.get('quantity', product['quantity'])
    
    cur.execute(
        "UPDATE Products SET name = %s, description = %s, price = %s, quantity = %s WHERE id = %s",
        (name, description, price, quantity, product_id)
    )
    mysql.connection.commit()
    cur.close()
    
    return jsonify({'message': 'Product updated successfully!'})

# Delete Product
@app.route('/products/<int:product_id>', methods=['DELETE'])
@token_required
def delete_product(current_user, product_id):
    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM Products WHERE id = %s", (product_id,))
    product = cur.fetchone()
    
    if not product:
        cur.close()
        return jsonify({'message': 'Product not found!'}), 404
    
    cur.execute("DELETE FROM Products WHERE id = %s", (product_id,))
    mysql.connection.commit()
    cur.close()
    
    return jsonify({'message': 'Product deleted successfully!'})

if __name__ == '__main__':
    app.run(debug=True)