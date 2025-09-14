import os
import time
import sqlite3
from flask import Flask, render_template, request, redirect, url_for, session, flash, g, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.secret_key = 'your_secret_key'
DATABASE = 'athleto.db'

db_path = os.path.abspath('receipt.db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
print('SQLAlchemy is using:', db_path)
db = SQLAlchemy(app)

# --- MODELS ---
class Receipt(db.Model):
    __tablename__ = 'receipts'
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer)
    user_email = db.Column(db.String)
    name = db.Column(db.String)
    contact = db.Column(db.String)
    address = db.Column(db.String)
    total = db.Column(db.Float)
    timestamp = db.Column(db.String)

    items = db.relationship('ReceiptItem', backref='receipt', lazy=True)

class ReceiptItem(db.Model):
    __tablename__ = 'receipt_items'
    id = db.Column(db.Integer, primary_key=True)
    receipt_id = db.Column(db.Integer, db.ForeignKey('receipts.id'))
    product_id = db.Column(db.String)
    name = db.Column(db.String)
    quantity = db.Column(db.Integer)
    price = db.Column(db.Float)
    subtotal = db.Column(db.Float)


# ==== PRODUCT STATIC ROUTE MAPPING ====
PRODUCT_ID_TO_ROUTE = {
    # Women Tops
    "top1_women": "/women/top/top1",
    "top2_women": "/women/top/top2",
    "top3_women": "/women/top/top3",
    "top4_women": "/women/top/top4",

    # Women Bottoms
    "bottoms1_women": "/women/bottoms/bottoms1",
    "bottoms2_women": "/women/bottoms/bottoms2",
    "bottoms3_women": "/women/bottoms/bottoms3",
    "bottoms4_women": "/women/bottoms/bottoms4",

    # Women Compressions
    "compressions1_women": "/women/compressions/compressions1",
    "compressions2_women": "/women/compressions/compressions2",
    "compressions3_women": "/women/compressions/compressions3",
    "compressions4_women": "/women/compressions/compressions4",

    # Women Dresses
    "dresses1_women": "/women/dresses/dresses1",
    "dresses2_women": "/women/dresses/dresses2",
    "dresses3_women": "/women/dresses/dresses3",
    "dresses4_women": "/women/dresses/dresses4",

    # Men Tops
    "top1_men": "/men/tops/top1",
    "top2_men": "/men/tops/top2",
    "top3_men": "/men/tops/top3",
    "top4_men": "/men/tops/top4",

    # Men Bottoms
    "bottom1_men": "/men/bottom/bottom1",
    "bottom2_men": "/men/bottom/bottom2",
    "bottom3_men": "/men/bottom/bottom3",
    "bottom4_men": "/men/bottom/bottom4",

    # Men Compressions
    "compression1_men": "/men/compression/compression1",
    "compression2_men": "/men/compression/compression2",
    "compression3_men": "/men/compression/compression3",
    "compression4_men": "/men/compression/compression4",

    # Men Terno
    "terno1_men": "/men/terno/terno1",
    "terno2_men": "/men/terno/terno2",
    "terno3_men": "/men/terno/terno3",
    "terno4_men": "/men/terno/terno4",

    # Accessories
    "accessories1": "/accessories_and_equipments/accessories/accessories1",
    "accessories2": "/accessories_and_equipments/accessories/accessories2",
    "accessories3": "/accessories_and_equipments/accessories/accessories3",
    "accessories4": "/accessories_and_equipments/accessories/accessories4",

    # Accessories Final
    "accessories_final1": "/accessories_and_equipments/accessories/accessories1/accessories_final1",

    # Equipments
    "equipments1": "/accessories_and_equipments/equipments/equipments1",
    "equipments2": "/accessories_and_equipments/equipments/equipments2",
    "equipments3": "/accessories_and_equipments/equipments/equipments3",
    "equipments4": "/accessories_and_equipments/equipments/equipments4",

    # Shoes
    "shoes1": "/shoes/shoes1",
    "shoes2": "/shoes/shoes2",
    "shoes3": "/shoes/shoes3",
    "shoes4": "/shoes/shoes4",
    "shoes5": "/shoes/shoes5",
    "shoes6": "/shoes/shoes6",
    "shoes7": "/shoes/shoes7",
    "shoes8": "/shoes/shoes8",
    "shoes9": "/shoes/shoes9",

    #shop1
    "shop1": "/shop1",

    #destination
    "destination1": "/destination1",
    "destination2": "/destination2",
    "destination3": "/destination3",
}

# ==== DATABASE HELPERS ====
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()

def get_product_db():
    if 'product_db' not in g:
        g.product_db = sqlite3.connect('products.db')
        g.product_db.row_factory = sqlite3.Row
    return g.product_db

@app.teardown_appcontext
def close_product_db(error):
    db = g.pop('product_db', None)
    if db is not None:
        db.close()

def get_product_by_id(product_id):
    db = get_product_db()
    c = db.cursor()
    c.execute('SELECT * FROM products WHERE product_id = ?', (product_id,))
    product = c.fetchone()
    return product

def get_all_products():
    db = get_product_db()
    c = db.cursor()
    c.execute('SELECT * FROM products')
    products = c.fetchall()
    return products

def init_db():
    db = get_db()
    db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT,
            is_admin INTEGER DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS carts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            product_id TEXT NOT NULL,
            size TEXT,
            quantity INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_email TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            name TEXT,
            contact TEXT,
            address TEXT,
            total_amount REAL NOT NULL
        );
        CREATE TABLE IF NOT EXISTS order_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            order_id INTEGER NOT NULL,
            product_id TEXT NOT NULL,
            name TEXT,
            size TEXT,
            quantity INTEGER NOT NULL,
            price REAL NOT NULL,
            image TEXT,
            FOREIGN KEY(order_id) REFERENCES orders(id)
        );
    """)
    db.commit()

def setup():
    init_db()
    db = get_db()
    admin_email = 'admin@athleto.com'
    admin = db.execute('SELECT * FROM users WHERE email = ?', (admin_email,)).fetchone()
    if not admin:
        db.execute("INSERT INTO users (email, password, name, is_admin) VALUES (?, ?, ?, ?)",
                   (admin_email, generate_password_hash('adminpass'), 'Admin User', 1))
        db.commit()

# ==== SESSION TIMEOUT ====
@app.before_request
def check_session_timeout():
    if 'user' in session:
        session_age = time.time() - session.get('timestamp', time.time())
        if session_age > 3600:
            session.clear()
            return redirect(url_for('signup'))
        else:
            session['timestamp'] = time.time()

# ==== AUTH DECORATORS ====

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user:
            flash('Email already registered. Please log in.', 'warning')
            return redirect(url_for('login'))
        password_hash = generate_password_hash(password)
        db.execute('INSERT INTO users (email, password, name, is_admin) VALUES (?, ?, ?, 0)',
                   (email, password_hash, name))
        db.commit()
        session['user'] = email
        session['timestamp'] = time.time()
        session['name'] = name
        session['is_admin'] = False
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email'].strip()
        password = request.form['password']
        db_ = get_db()
        user = db_.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        if user and check_password_hash(user['password'], password):
            session['user'] = user['email']
            session['name'] = user['name']
            session['is_admin'] = bool(user['is_admin'])
            session['timestamp'] = time.time()
            flash('Welcome back!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    return render_template('login.html')


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))



# ==== ADMIN ROUTES ====
import re
from flask import request, render_template
from sqlalchemy import or_, and_

@app.route('/admin/receipts')
@admin_required
def admin_receipts():
    search = request.args.get('search', '').strip()
    query = Receipt.query

    if search:
        # --- ID Range: id 1-20 or ID 1-20 ---
        id_range = re.search(r'\bid\s*(\d+)\s*-\s*(\d+)', search, re.I)
        if id_range:
            min_id, max_id = map(int, id_range.groups())
            query = query.filter(Receipt.id.between(min_id, max_id))
        
        # --- Total Range: total 5000-10000 ---
        total_range = re.search(r'\btotal\s*(\d+)\s*-\s*(\d+)', search, re.I)
        if total_range:
            min_total, max_total = map(float, total_range.groups())
            query = query.filter(Receipt.total.between(min_total, max_total))
        
        # --- Date Range: date:YYYY-MM-DD:YYYY-MM-DD ---
        date_range = re.search(r'\bdate:(\d{4}-\d{2}-\d{2}):(\d{4}-\d{2}-\d{2})', search, re.I)
        if date_range:
            from_date, to_date = date_range.groups()
            query = query.filter(Receipt.timestamp.between(from_date, to_date))
        
        # --- Year: year:YYYY ---
        year_match = re.search(r'\byear:(\d{4})\b', search, re.I)
        if year_match:
            year = year_match.group(1)
            query = query.filter(
                Receipt.timestamp >= f"{year}-01-01",
                Receipt.timestamp <= f"{year}-12-31"
            )

        # --- Generic Range (if only numbers and dash): 5000-10000 (assume total) ---
        generic_range = re.match(r'^\s*(\d+)\s*-\s*(\d+)\s*$', search)
        if generic_range and not (id_range or total_range):
            min_total, max_total = map(float, generic_range.groups())
            query = query.filter(Receipt.total.between(min_total, max_total))
        
        # --- Fallback: number as ID or total ---
        elif not (id_range or total_range or date_range or year_match):
            try:
                number = float(search)
                query = query.filter((Receipt.id == int(number)) | (Receipt.total == number))
            except ValueError:
                # --- Free text fallback: ---
                like = f"%{search}%"
                query = query.filter(
                    or_(
                        Receipt.user_email.ilike(like),
                        Receipt.name.ilike(like),
                        Receipt.contact.ilike(like),
                        Receipt.address.ilike(like),
                        db.cast(Receipt.id, db.String).ilike(like),
                        db.cast(Receipt.total, db.String).ilike(like),
                        db.cast(Receipt.timestamp, db.String).ilike(like),
                    )
                )

    receipts = query.order_by(Receipt.timestamp.desc()).all()
    detailed_receipts = [{'receipt': r, 'items': r.items} for r in receipts]
    return render_template('admin_user_receipts.html', receipts=detailed_receipts)
def get_order_by_id_and_email(order_id, email):
    db = get_db()
    order = db.execute(
        'SELECT * FROM orders WHERE id = ? AND user_email = ?', 
        (order_id, email)
    ).fetchone()
    if order:
        return dict(order)
    return None

@app.route('/tracker.html')
def tracker():
    order_id = request.args.get('order_id')
    email = request.args.get('email')
    order = None
    order_timestamp = None
    if order_id and email:
        order = get_order_by_id_and_email(order_id, email)
        if order:
            order_timestamp = order['timestamp']
    if not order:
        return render_template('tracker.html', order_id=order_id, order_email=email, order_timestamp="")
    return render_template(
        'tracker.html',
        order_id=order_id,
        order_email=email,
        order_timestamp=order_timestamp
    )

# ==== RECEIPT ROUTES ==== 
@app.route('/user_receipt/<int:order_id>') 
def user_receipt(order_id): 
    if 'user' not in session: 
        return redirect(url_for('login')) 
    db = get_db() 
    order = db.execute('SELECT * FROM orders WHERE id = ? AND user_email = ?', (order_id, 
session['user'])).fetchone() 
    if not order: 
        abort(404) 
    items = db.execute('SELECT * FROM order_items WHERE order_id = ?', (order_id,)).fetchall() 
    return render_template('user_receipt.html', order=order, items=items)

import re
from datetime import datetime
def parse_date_range(search):
    # Try to match with or without time
    m = re.search(r'date:(\d{4}-\d{2}-\d{2})( \d{2}:\d{2})?( \d{4}-\d{2}-\d{2})( \d{2}:\d{2})?', search)
    if m:
        start_date = m.group(1)
        start_time = m.group(2) or ' 00:00'
        end_date = m.group(3)
        end_time = m.group(4) or ' 23:59'
        start = f"{start_date}{start_time}:00"
        end = f"{end_date}{end_time}:59"
        return start.strip(), end.strip()
    return None, None

# Usage in your route or function
def some_route_or_function():
    search = "date:2025-06-01 12:00 2025-06-24 15:00"  # Example input, replace as needed
    date_range = parse_date_range(search)

    from models import Receipt  # or wherever your Receipt model is
    query = Receipt.query  # or session.query(Receipt) if using SQLAlchemy session

    if date_range[0] and date_range[1]:
        query = query.filter(Receipt.timestamp.between(date_range[0], date_range[1]))

    # Continue with your logic...

def parse_search_advanced(query):
    # Returns a dict of filters
    import re
    filters = {}
    # ID range: "ID 1-20" or "id 1-20"
    m = re.search(r'\bID\s*(\d+)\s*-\s*(\d+)', query, re.IGNORECASE)
    if m:
        filters["id_range"] = (int(m.group(1)), int(m.group(2)))
    # Total range: "total 5000-10000"
    m = re.search(r'\btotal\s*(\d+)\s*-\s*(\d+)', query, re.IGNORECASE)
    if m:
        filters["total_range"] = (int(m.group(1)), int(m.group(2)))
    # Year: "year:2024"
    m = re.search(r'\byear:(\d{4})', query, re.IGNORECASE)
    if m:
        filters["year"] = int(m.group(1))
    # Date range: "date:2024-01-01:2024-06-01"
    m = re.search(r'\bdate:(\d{4}-\d{2}-\d{2}):(\d{4}-\d{2}-\d{2})', query, re.IGNORECASE)
    if m:
        filters["date_range"] = (m.group(1), m.group(2))
    # General search: anything else
    filters["general"] = query
    return filters
@app.route('/admin_dashboard')
def admin_dashboard():
    db = get_db()
    search = request.args.get('search', '').strip()

    # --- Orders search logic ---
    base_query = 'SELECT * FROM orders'
    filters = []
    params = []

    if search:
        # Order ID range: "Order ID 1-20"
        m_id_range = re.search(r'order\s*id\s*(\d+)\s*-\s*(\d+)', search, re.IGNORECASE)
        if m_id_range:
            filters.append('id BETWEEN ? AND ?')
            params.extend([int(m_id_range.group(1)), int(m_id_range.group(2))])

        # Amount range: "1000-5000"
        m_amount = re.search(r'(\d+)\s*-\s*(\d+)', search)
        if m_amount and not m_id_range:  # avoid conflict with ID range
            filters.append('total_amount BETWEEN ? AND ?')
            params.extend([float(m_amount.group(1)), float(m_amount.group(2))])

        # Email
        m_email = re.search(r'([\w\.-]+@[\w\.-]+)', search)
        if m_email:
            filters.append('user_email LIKE ?')
            params.append(f"%{m_email.group(1)}%")

        # Date (YYYY-MM-DD)
        m_date = re.search(r'(\d{4}-\d{2}-\d{2})', search)
        if m_date:
            filters.append('timestamp LIKE ?')
            params.append(f"{m_date.group(1)}%")

        # Fallback: generic search (by user email or order id)
        if not filters:
            filters.append('(user_email LIKE ? OR id = ?)')
            params.extend([f"%{search}%", search if search.isdigit() else -1])

    query = base_query
    if filters:
        query += " WHERE " + " AND ".join(filters)
    query += ' ORDER BY timestamp DESC'

    all_orders = db.execute(query, params).fetchall()
    orders_with_products = []
    for order in all_orders:
        items = db.execute('SELECT name, quantity, size FROM order_items WHERE order_id = ?', (order['id'],)).fetchall()
        orders_with_products.append({
            **dict(order),
            'items': [dict(i) for i in items]
        })

    # Fetch users and feedbacks (unchanged)
    users = db.execute('SELECT id, email, name, is_admin FROM users').fetchall()
    feedback_db = get_feedback_db()
    feedbacks = feedback_db.execute('SELECT * FROM web_feedback ORDER BY created_at DESC').fetchall()
    return render_template(
        'admin_dashboard.html',
        users=users,
        orders=orders_with_products,
        feedbacks=feedbacks
    )

@app.route('/admin/receipts/<int:receipt_id>/items')
@admin_required
def admin_receipt_items(receipt_id):
    db = get_receipt_db()
    receipt = db.execute('SELECT * FROM receipts WHERE id = ?', (receipt_id,)).fetchone()
    if not receipt:
        flash('Receipt not found.', 'danger')
        return redirect(url_for('admin_receipts'))
    items = db.execute('SELECT * FROM receipt_items WHERE receipt_id = ?', (receipt_id,)).fetchall()
    return render_template('admin_receipt_items.html', receipt=receipt, items=items)

@app.route('/admin/users')
@admin_required
def admin_users():
    db = get_db()
    users = db.execute('SELECT id, email, name, is_admin FROM users').fetchall()
    return render_template('admin_users.html', users=users)

@app.route('/admin/make_admin/<int:user_id>', methods=['POST'])
@admin_required
def make_admin(user_id):
    db = get_db()
    db.execute('UPDATE users SET is_admin = 1 WHERE id = ?', (user_id,))
    db.commit()
    flash('User promoted to admin.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/remove_admin/<int:user_id>', methods=['POST'])
@admin_required
def remove_admin(user_id):
    db = get_db()
    db.execute('UPDATE users SET is_admin = 0 WHERE id = ?', (user_id,))
    db.commit()
    flash('User admin rights removed.', 'success')
    return redirect(url_for('admin_users'))

@app.route('/admin/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    flash('User deleted.', 'success')
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/user_orders/<int:user_id>')
@admin_required
def admin_user_orders(user_id):
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('admin_users'))
    orders = db.execute('SELECT * FROM orders WHERE user_email = ?', (user['email'],)).fetchall()
    order_data = []
    for order in orders:
        items = db.execute('SELECT * FROM order_items WHERE order_id = ?', (order['id'],)).fetchall()
        order_data.append({'order': order, 'items': items})
    return render_template('admin_user_orders.html', user=user, orders=order_data)

# ==== USER DASHBOARD ====
@app.route('/dashboard')
def dashboard():
    if "user" not in session:
        return redirect(url_for("login"))

    db = get_db()
    # Get all orders for the user
    orders = db.execute('SELECT * FROM orders WHERE user_email = ? ORDER BY timestamp DESC', (session["user"],)).fetchall()
    order_data = []
    for order in orders:
        items = db.execute('SELECT * FROM order_items WHERE order_id = ?', (order['id'],)).fetchall()
        order_data.append({'order': order, 'items': items})

    # --- FEEDBACK BUTTON LOGIC ---
    # Connect to feedback.db for product_feedback
    import sqlite3
    feedback_db = sqlite3.connect('feedback.db')
    feedback_db.row_factory = sqlite3.Row

    show_feedback_button = False
    delivered_order_id = None

    # Find most recent delivered order with no feedback
    delivered_orders = db.execute(
        "SELECT id FROM orders WHERE user_email = ? AND status = 'Delivered' ORDER BY timestamp DESC",
        (session["user"],)
    ).fetchall()
    for o in delivered_orders:
        feedback = feedback_db.execute(
            "SELECT 1 FROM product_feedback WHERE order_id = ?", (o['id'],)
        ).fetchone()
        if not feedback:
            show_feedback_button = True
            delivered_order_id = o['id']
            break

    feedback_db.close()
    # --- END FEEDBACK BUTTON LOGIC ---

    return render_template(
        "dashboard.html",
        orders=order_data,
        show_feedback_button=show_feedback_button,
        delivered_order_id=delivered_order_id
    )
# ==== CART HELPERS ====
def get_cart(user_email):
    db = get_db()
    rows = db.execute('SELECT * FROM carts WHERE user_email = ?', (user_email,)).fetchall()
    cart = []
    product_db = get_product_db()
    for r in rows:
        product = get_product_by_id(r['product_id'])
        if product:
            if is_shoe_product(r['product_id']):
                stock_row = product_db.execute(
                    'SELECT stock FROM shoe_sizes WHERE product_id = ? AND size = ?',
                    (r['product_id'], r['size'])
                ).fetchone()
            else:
                stock_row = product_db.execute(
                    'SELECT stock FROM product_sizes WHERE product_id = ? AND size = ?',
                    (r['product_id'], r['size'])
                ).fetchone()
            size_stock = stock_row['stock'] if stock_row else 0
            cart.append({
                'product_id': r['product_id'],
                'name': product['name'],
                'quantity': r['quantity'],
                'size': r['size'],
                'price': product['price'],
                'image': url_for('static', filename=product['image']),
                'stock': size_stock
            })
    return cart

@app.route('/admin/add_stock/<product_id>', methods=['POST'])
@admin_required
def add_stock(product_id):
    amount = int(request.form.get('amount', 0))
    if amount > 0:
        conn = sqlite3.connect('products.db')
        conn.execute('UPDATE products SET stock = stock + ? WHERE product_id = ?', (amount, product_id))
        conn.commit()
        conn.close()
        flash(f"Added {amount} stock to {product_id}.", "success")
    else:
        flash("Invalid stock amount.", "danger")
    return redirect(url_for('view_products_db'))

def get_cart_count(user_email):
    db = get_db()
    row = db.execute('SELECT SUM(quantity) as total FROM carts WHERE user_email = ?', (user_email,)).fetchone()
    return row['total'] or 0

def save_cart_item(user_email, product_id, size, quantity):
    db = get_db()
    row = db.execute('SELECT * FROM carts WHERE user_email = ? AND product_id = ? AND size = ?',
                     (user_email, product_id, size)).fetchone()
    if row:
        db.execute('UPDATE carts SET quantity = quantity + ? WHERE id = ?', (quantity, row['id']))
    else:
        db.execute('INSERT INTO carts (user_email, product_id, size, quantity) VALUES (?, ?, ?, ?)',
                   (user_email, product_id, size, quantity))
    db.commit()

def update_cart_item(user_email, product_id, size, new_quantity):
    db = get_db()
    if new_quantity <= 0:
        db.execute('DELETE FROM carts WHERE user_email = ? AND product_id = ? AND size = ?',
                   (user_email, product_id, size))
    else:
        db.execute('UPDATE carts SET quantity = ? WHERE user_email = ? AND product_id = ? AND size = ?',
                   (new_quantity, user_email, product_id, size))
    db.commit()

def clear_cart(user_email):
    db = get_db()
    db.execute('DELETE FROM carts WHERE user_email = ?', (user_email,))
    db.commit()

# ==== CART ROUTES ====
@app.route('/cart')
def view_cart():
    if 'user' not in session:
        return redirect(url_for('login'))
    cart = get_cart(session['user'])
    total = sum(item['price'] * item['quantity'] for item in cart)
    for item in cart:
        item['subtotal'] = item['price'] * item['quantity']
    return render_template('cart.html', cart=cart, total=total)

@app.route('/add_to_cart/<product_id>', methods=['POST'])
def add_to_cart(product_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    quantity = int(request.form.get('quantity', 1))
    size = request.form.get('size') or ''
    product = get_product_by_id(product_id)
    if not product:
        return "Product not found", 404

    product_db = get_product_db()

    # --- Extra1-20 stock logic ---
    def is_extra_product(product_id):
        return product_id.startswith('Extra') and product_id[5:].isdigit() and 1 <= int(product_id[5:]) <= 20

    if is_shoe_product(product_id):
        stock_row = product_db.execute(
            'SELECT stock FROM shoe_sizes WHERE product_id = ? AND size = ?',
            (product_id, size)
        ).fetchone()
    elif is_accessory_product(product_id) or is_equipment_product(product_id) or is_extra_product(product_id):
        # Accessories, Equipments, and Extra1-20: stock is in item_stocks table, ignore size
        stock_row = product_db.execute(
            'SELECT stock FROM item_stocks WHERE product_id = ?',
            (product_id,)
        ).fetchone()
        size = 'Standard'  # For cart consistency, set size as 'Standard' for these products
    else:
        stock_row = product_db.execute(
            'SELECT stock FROM product_sizes WHERE product_id = ? AND size = ?',
            (product_id, size)
        ).fetchone()

    if not stock_row or stock_row['stock'] < 1:
        route = PRODUCT_ID_TO_ROUTE.get(product_id)
        return redirect(route) if route else redirect(url_for('home'))

    # Check how many are already in cart
    db = get_db()
    row = db.execute('SELECT quantity FROM carts WHERE user_email = ? AND product_id = ? AND size = ?',
                     (session['user'], product_id, size)).fetchone()
    already_in_cart = row['quantity'] if row else 0

    # Do not allow adding more than available stock
    if already_in_cart + quantity > stock_row['stock']:
        flash('Not enough stock available.', 'danger')
        route = PRODUCT_ID_TO_ROUTE.get(product_id)
        return redirect(route) if route else redirect(url_for('home'))

    # Add to cart
    if row:
        db.execute('UPDATE carts SET quantity = quantity + ? WHERE user_email = ? AND product_id = ? AND size = ?',
                   (quantity, session['user'], product_id, size))
    else:
        db.execute('INSERT INTO carts (user_email, product_id, size, quantity) VALUES (?, ?, ?, ?)',
                   (session['user'], product_id, size, quantity))
    db.commit()
    return redirect(url_for('view_cart'))


@app.route('/api/cart/update', methods=['POST'])
def api_update_cart():
    if 'user' not in session:
        return jsonify({'success': False, 'msg': 'Not logged in'}), 401
    product_id = request.form.get('product_id')
    action = request.form.get('action')
    size = request.form.get('size') or ''
    db = get_db()
    row = db.execute(
        'SELECT * FROM carts WHERE user_email = ? AND product_id = ? AND size = ?',
        (session['user'], product_id, size)
    ).fetchone()
    item_quantity = 0
    item_subtotal = 0
    product = get_product_by_id(product_id)
    item_price = float(product['price']) if product else 0
    if row:
        if action == 'increase':
            new_qty = row['quantity'] + 1
        elif action == 'decrease':
            new_qty = row['quantity'] - 1
        else:
            new_qty = row['quantity']
        if new_qty <= 0:
            db.execute('DELETE FROM carts WHERE id = ?', (row['id'],))
        else:
            db.execute('UPDATE carts SET quantity = ? WHERE id = ?', (new_qty, row['id']))
        db.commit()
        updated_row = db.execute(
            'SELECT * FROM carts WHERE id = ?', (row['id'],)
        ).fetchone() if new_qty > 0 else None
        item_quantity = updated_row['quantity'] if updated_row else 0
        item_subtotal = (updated_row['quantity'] * item_price) if updated_row else 0
    cart_rows = db.execute(
        'SELECT product_id, quantity, size FROM carts WHERE user_email = ?',
        (session['user'],)
    ).fetchall()
    cart_total = sum(
        r['quantity'] * float(get_product_by_id(r['product_id'])['price'])
        for r in cart_rows if get_product_by_id(r['product_id'])
    )
    return jsonify({
        'success': True,
        'item_quantity': item_quantity,
        'item_subtotal': item_subtotal,
        'cart_total': cart_total
    })

# ==== ORDER ROUTES ====
@app.route('/checkout', methods=['GET', 'POST'])
def checkout():
    if 'user' not in session:
        return redirect(url_for('login'))
    cart = get_cart(session['user'])
    info = session.get('checkout_info')
    if not info:
        # Redirect to form if no shipping info
        return redirect(url_for('checkout_info'))
    if request.method == 'POST':
        # If you want to allow editing shipping info from confirm page
        return redirect(url_for('checkout_info'))
    # User reviews order and submits form to /checkout/order
    return render_template('checkout.html', cart=cart, step='confirm', info=info)


@app.route('/checkout/confirm', methods=['POST'])
def checkout_confirm():
    if 'user' not in session:
        return redirect(url_for('login'))

    user_email = session['user']
    cart = get_cart(user_email)
    info = session.get('checkout_info', {})

    if not cart or not info:
        flash('Missing cart or shipping information. Please try again.', 'danger')
        return redirect(url_for('view_cart'))

    db = get_db()
    product_db = get_product_db()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total = sum(item['price'] * item['quantity'] for item in cart)
    address = f"{info.get('home_number', '')}, {info.get('barangay', '')}, {info.get('city', '')}, {info.get('province', '')}, {info.get('region', '')}"

    # --- Check stock again before placing order (same as before) ---
    # [ ... your existing code ... ]

    # Save order
    cur = db.execute(
        'INSERT INTO orders (user_email, timestamp, name, contact, address, total_amount) VALUES (?, ?, ?, ?, ?, ?)',
        (user_email, timestamp, info.get('name', ''), info.get('contact', ''), address, total)
    )
    order_id = cur.lastrowid

    # Save order items
    for item in cart:
        db.execute(
            'INSERT INTO order_items (order_id, product_id, name, size, quantity, price, image) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (order_id, item['product_id'], item['name'], item['size'], item['quantity'], item['price'], item['image'])
        )
    db.commit()

    # [ ... your stock deduction code ... ]

    # ========== NEW/UPDATED BLOCK TO SAVE RECEIPT ==========
    # Save receipt in receipt.db (NO local import of datetime!)
    items_list = [
        {
            'product_id': item['product_id'],
            'name': item['name'],
            'quantity': item['quantity'],
            'price': item['price']
        }
        for item in cart
    ]
    # Use the same formatted address as above
    save_receipt(
        order_id,
        user_email,
        info.get('name', ''),
        info.get('contact', ''),
        address,
        total,
        items_list
    )
    # ========== END RECEIPT BLOCK ==========

    # --- Clear cart and shipping info from session ---
    clear_cart(user_email)
    session.pop('checkout_info', None)

    return render_template('confirmed.html', order_id=order_id)

@app.route('/checkout/order', methods=['POST'])
def checkout_order():
    if 'user' not in session:
        return redirect(url_for('login'))
    cart = get_cart(session['user'])
    if not cart:
        flash('No product to confirm. Please return to the shop.', 'danger')
        return redirect(url_for('home'))

    # Get form fields
    name = request.form.get("name", "").strip()
    contact = request.form.get("contact", "").strip()
    region = request.form.get("region", "").strip()
    province = request.form.get("province", "").strip()
    city = request.form.get("city", "").strip()
    barangay = request.form.get("barangay", "").strip()
    postal = request.form.get("postal", "").strip()
    home_number = request.form.get("home_number", "").strip()
    address = f"{home_number}, {barangay}, {city}, {province}, {region}, {postal}"
    payment_method = request.form.get("payment_mode", "").strip().lower()

    # --- Optionally: Validate payment details here ---
    error = None
    if payment_method == "gcash":
        gcash_number = request.form.get("gcash_number", "").strip()
        gcash_name = request.form.get("gcash_name", "").strip()
        if not gcash_number or not gcash_number.startswith('09') or len(gcash_number) != 11 or not gcash_number.isdigit():
            error = "Invalid GCash number. It must start with 09 and be 11 digits."
        elif not gcash_name:
            error = "GCash account name required."
    elif payment_method == "paymaya":
        paymaya_number = request.form.get("paymaya_number", "").strip()
        paymaya_name = request.form.get("paymaya_name", "").strip()
        if not paymaya_number or not paymaya_number.startswith('09') or len(paymaya_number) != 11 or not paymaya_number.isdigit():
            error = "Invalid PayMaya number. It must start with 09 and be 11 digits."
        elif not paymaya_name:
            error = "PayMaya account name required."
    elif payment_method == "bdo":
        bdo_account_number = request.form.get("bdo_account_number", "").strip()
        bdo_account_name = request.form.get("bdo_account_name", "").strip()
        if not bdo_account_number or not bdo_account_number.isdigit() or not (10 <= len(bdo_account_number) <= 12):
            error = "Invalid BDO account number. It must be 10 to 12 digits."
        elif not bdo_account_name:
            error = "BDO account name required."
    elif payment_method == "bpi":
        bpi_account_number = request.form.get("bpi_account_number", "").strip()
        bpi_account_name = request.form.get("bpi_account_name", "").strip()
        if not bpi_account_number or not bpi_account_number.isdigit() or not (10 <= len(bpi_account_number) <= 12):
            error = "Invalid BPI account number. It must be 10 to 12 digits."
        elif not bpi_account_name:
            error = "BPI account name required."
    if error:
        flash(error, "danger")
        return redirect(url_for('checkout'))

    # For all payment methods, process the receipt and order immediately
    total = sum(item['price'] * item['quantity'] for item in cart)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    user_email = session['user']

    # --- Check stock before placing order ---
    product_db = get_product_db()
    for item in cart:
        if is_shoe_product(item['product_id']):
            row = product_db.execute(
                'SELECT stock FROM shoe_sizes WHERE product_id = ? AND size = ?',
                (item['product_id'], item['size'])
            ).fetchone()
        elif is_accessory_product(item['product_id']) or is_equipment_product(item['product_id']):
            row = product_db.execute(
                'SELECT stock FROM item_stocks WHERE product_id = ?',
                (item['product_id'],)
            ).fetchone()
        else:
            row = product_db.execute(
                'SELECT stock FROM product_sizes WHERE product_id = ? AND size = ?',
                (item['product_id'], item['size'])
            ).fetchone()
        if not row or row['stock'] < item['quantity']:
            flash(f"Not enough stock for {item['name']}! Only {row['stock'] if row else 0} left.", "danger")
            route = PRODUCT_ID_TO_ROUTE.get(item['product_id'])
            if route:
                return redirect(route)
            else:
                return redirect(url_for('view_cart'))

    # --- Place the order in orders.db ---
    db = get_db()
    cur = db.execute(
        'INSERT INTO orders (user_email, timestamp, name, contact, address, total_amount) VALUES (?, ?, ?, ?, ?, ?)',
        (user_email, timestamp, name, contact, address, total)
    )
    order_id = cur.lastrowid

    for item in cart:
        db.execute(
            'INSERT INTO order_items (order_id, product_id, name, size, quantity, price, image) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (order_id, item['product_id'], item['name'], item['size'], item['quantity'], item['price'], item['image'])
        )
    db.commit()

    # Deduct stock
    for item in cart:
        if is_shoe_product(item['product_id']):
            product_db.execute(
                'UPDATE shoe_sizes SET stock = stock - ? WHERE product_id = ? AND size = ? AND stock >= ?',
                (item['quantity'], item['product_id'], item['size'], item['quantity'])
            )
        elif is_accessory_product(item['product_id']) or is_equipment_product(item['product_id']):
            product_db.execute(
                'UPDATE item_stocks SET stock = stock - ? WHERE product_id = ? AND stock >= ?',
                (item['quantity'], item['product_id'], item['quantity'])
            )
        else:
            product_db.execute(
                'UPDATE product_sizes SET stock = stock - ? WHERE product_id = ? AND size = ? AND stock >= ?',
                (item['quantity'], item['product_id'], item['size'], item['quantity'])
            )
    product_db.commit()

    # Save receipt in receipt.db with only payment_method (not account numbers/names)
    items_list = [
        {
            'product_id': item['product_id'],
            'name': item['name'],
            'quantity': item['quantity'],
            'price': item['price']
        }
        for item in cart
    ]
    save_receipt(
        order_id,
        user_email,
        name,
        contact,
        address,
        total,
        items_list,
        payment_method=payment_method
    )

    clear_cart(session['user'])

    # Show the thank-you/confirmation page
    return render_template('confirmed.html', order_id=order_id)


def save_receipt(
    order_id,
    user_email,
    name,
    contact,
    address,
    total,
    items_list,
    payment_method=None
):
    receipt_db = get_receipt_db()
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Insert into receipts with payment_method only
    receipt_cur = receipt_db.execute(
        '''
        INSERT INTO receipts (
            order_id, user_email, name, contact, address, total, timestamp, payment_method
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            order_id, user_email, name, contact, address, total, timestamp, payment_method
        )
    )
    receipt_id = receipt_cur.lastrowid

    for item in items_list:
        subtotal = item['price'] * item['quantity']
        receipt_db.execute(
            'INSERT INTO receipt_items (receipt_id, product_id, name, quantity, price, subtotal) VALUES (?, ?, ?, ?, ?, ?)',
            (receipt_id, item['product_id'], item['name'], item['quantity'], item['price'], subtotal)
        )
    receipt_db.commit()

@app.route('/checkout/info', methods=['GET', 'POST'])
def checkout_info():
    if 'user' not in session:
        return redirect(url_for('login'))
    cart = get_cart(session['user'])
    info = session.get('checkout_info', {})
    if request.method == 'POST':
        info = {
            'name': request.form.get('name', ''),
            'contact': request.form.get('contact', ''),
            'region': request.form.get('region', ''),
            'province': request.form.get('province', ''),
            'city': request.form.get('city', ''),
            'barangay': request.form.get('barangay', ''),
            'home_number': request.form.get('home_number', ''),
        }
        session['checkout_info'] = info
        return redirect(url_for('checkout'))  # Go to confirm step
    return render_template('checkout.html', cart=cart, step='info', info=info)




@app.route('/buy_now_shipping/<product_id>', methods=['GET', 'POST'])
def buy_now_shipping(product_id):
    if 'user' not in session or 'buy_now' not in session:
        flash('Please start your purchase from the product page', 'warning')
        return redirect(url_for('home'))

    if session['buy_now'].get('product_id') != product_id:
        flash('Invalid product in session', 'danger')
        return redirect(url_for('home'))

    product = get_product_by_id(product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('home'))

    # Helper for Extra1–20
    def is_extra_product(product_id):
        return product_id.startswith('Extra') and product_id[5:].isdigit() and 1 <= int(product_id[5:]) <= 20

    if request.method == 'POST':
        # Validate required fields
        required_fields = ['name', 'contact', 'region', 'province', 'city', 'barangay', 'home_number', 'payment_mode']
        if not all(request.form.get(field) for field in required_fields):
            flash('Please fill all required fields', 'danger')
            return redirect(url_for('buy_now_shipping', product_id=product_id))

        # Update session with shipping info & payment info
        session['buy_now'].update({
            'name': request.form['name'],
            'contact': request.form['contact'],
            'region': request.form['region'],
            'province': request.form['province'],
            'city': request.form['city'],
            'barangay': request.form['barangay'],
            'home_number': request.form['home_number'],
            'address': f"{request.form['home_number']}, {request.form['barangay']}, {request.form['city']}, {request.form['province']}, {request.form['region']}",
            'payment_method': request.form.get('payment_mode', ''),
            'gcash_number': request.form.get('gcash_number', ''),
            'gcash_name': request.form.get('gcash_name', ''),
            'paymaya_number': request.form.get('paymaya_number', ''),
            'paymaya_name': request.form.get('paymaya_name', ''),
            'bdo_account_number': request.form.get('bdo_account_number', ''),
            'bdo_account_name': request.form.get('bdo_account_name', ''),
            'bpi_account_number': request.form.get('bpi_account_number', ''),
            'bpi_account_name': request.form.get('bpi_account_name', '')
        })
        # For Extra1–20, enforce 'Standard' size in session for consistency downstream
        if is_extra_product(product_id):
            session['buy_now']['size'] = 'Standard'
        session.modified = True

        return redirect(url_for('confirm_purchase', product_id=product_id))

    # GET request - show shipping form
    # For Extra1–20, show always 'Standard' for size
    size = session['buy_now'].get('size', '')
    if is_extra_product(product_id):
        size = 'Standard'

    return render_template(
        'buy_now_shipping.html',
        product=product,
        product_id=product_id,
        size=size,
        quantity=session['buy_now'].get('quantity', 1),
        price=session['buy_now'].get('price', product['price'])
    )

def is_extra_product(product_id):
    return product_id.startswith('Extra') and product_id[5:].isdigit() and 1 <= int(product_id[5:]) <= 20


def is_shoe_product(product_id):
    # Extra21 and Extra22 are shoes
    return product_id.startswith('shoes') or product_id in ['Extra21', 'Extra22']

def is_accessory_product(product_id):
    # Accessories: not shoes, not cloth
    return product_id.startswith('accessories') and product_id not in ['Extra21', 'Extra22', 'Extra23']

def is_equipment_product(product_id):
    return product_id.startswith('equipments')

def is_cloth_product(product_id):
    # Extra23 is a cloth
    return product_id == 'Extra23'

import re

@app.route('/confirm_purchase/<product_id>', methods=['GET', 'POST'])
def confirm_purchase(product_id):
    if 'user' not in session or 'buy_now' not in session:
        flash('Please complete your order information first', 'warning')
        return redirect(url_for('home'))

    if session['buy_now'].get('product_id') != product_id:
        flash('Invalid product in session', 'danger')
        return redirect(url_for('home'))

    product = get_product_by_id(product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('home'))

    buy_now = session['buy_now']

    # --- Payment/Account Field Extraction ---
    payment_method = buy_now.get('payment_method', '').lower()
    gcash_number = buy_now.get('gcash_number', '')
    gcash_name = buy_now.get('gcash_name', '')
    paymaya_number = buy_now.get('paymaya_number', '')
    paymaya_name = buy_now.get('paymaya_name', '')
    bdo_account_number = buy_now.get('bdo_account_number', '')
    bdo_account_name = buy_now.get('bdo_account_name', '')
    bpi_account_number = buy_now.get('bpi_account_number', '')
    bpi_account_name = buy_now.get('bpi_account_name', '')

    error = None

    if request.method == 'POST':
        # --- VALIDATION START ---

        # GCash
        if payment_method == "gcash":
            if not re.fullmatch(r'09\d{9}', gcash_number or ''):
                error = 'GCash number must be 11 digits and start with "09".'
            if not gcash_name.strip():
                error = 'GCash account name is required.'

        # PayMaya
        if payment_method == "paymaya":
            if not re.fullmatch(r'09\d{9}', paymaya_number or ''):
                error = 'PayMaya number must be 11 digits and start with "09".'
            if not paymaya_name.strip():
                error = 'PayMaya account name is required.'

        # BDO
        if payment_method == "bdo":
            if not re.fullmatch(r'\d{10,12}', bdo_account_number or ''):
                error = 'BDO account number must be 10-12 digits.'
            if not bdo_account_name.strip():
                error = 'BDO account name is required.'

        # BPI
        if payment_method == "bpi":
            if not re.fullmatch(r'\d{10,12}', bpi_account_number or ''):
                error = 'BPI account number must be 10-12 digits.'
            if not bpi_account_name.strip():
                error = 'BPI account name is required.'

        # If validation failed, show error and re-render
        if error:
            flash(error, 'danger')
            return render_template(
                'confirm_purchase.html',
                product=product,
                product_id=product_id,
                size=buy_now.get('size', ''),
                quantity=buy_now.get('quantity', 1),
                price=float(buy_now.get('price', product['price'])),
                total=float(buy_now.get('price', product['price'])) * int(buy_now.get('quantity', 1)),
                name=buy_now.get('name', ''),
                contact=buy_now.get('contact', ''),
                home_number=buy_now.get('home_number', ''),
                barangay=buy_now.get('barangay', ''),
                city=buy_now.get('city', ''),
                province=buy_now.get('province', ''),
                region=buy_now.get('region', ''),
                address=buy_now.get('address', ''),
                payment_method=buy_now.get('payment_method', ''),
                gcash_number=gcash_number,
                gcash_name=gcash_name,
                paymaya_number=paymaya_number,
                paymaya_name=paymaya_name,
                bdo_account_number=bdo_account_number,
                bdo_account_name=bdo_account_name,
                bpi_account_number=bpi_account_number,
                bpi_account_name=bpi_account_name
            )

        # --- STOCK CHECK ---
        db = get_db()
        product_db = get_product_db()
        receipt_db = get_receipt_db()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = float(buy_now['price']) * int(buy_now['quantity'])

        if is_shoe_product(product_id):
            row = product_db.execute(
                'SELECT stock FROM shoe_sizes WHERE product_id = ? AND size = ?',
                (product_id, buy_now['size'])
            ).fetchone()
        elif is_accessory_product(product_id) or is_equipment_product(product_id):
            row = product_db.execute(
                'SELECT stock FROM item_stocks WHERE product_id = ?',
                (product_id,)
            ).fetchone()
        else:
            row = product_db.execute(
                'SELECT stock FROM product_sizes WHERE product_id = ? AND size = ?',
                (product_id, buy_now['size'])
            ).fetchone()
        if not row or row['stock'] < buy_now['quantity']:
            flash('Insufficient stock.', 'danger')
            return redirect(url_for('buy_now_shipping', product_id=product_id))

        # --- ORDER CREATION ---
        cur = db.execute(
            'INSERT INTO orders (user_email, timestamp, name, contact, address, total_amount) VALUES (?, ?, ?, ?, ?, ?)',
            (session['user'], timestamp, buy_now['name'], buy_now['contact'], buy_now['address'], total)
        )
        order_id = cur.lastrowid

        db.execute(
            'INSERT INTO order_items (order_id, product_id, name, size, quantity, price, image) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (order_id, product_id, product['name'], buy_now['size'], buy_now['quantity'], buy_now['price'], product['image'])
        )

        # --- RECEIPT RECORD ---
        receipt_db.execute(
            'INSERT INTO receipts (order_id, user_email, name, contact, address, total, timestamp, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (
                order_id,
                session['user'],
                buy_now['name'],
                buy_now['contact'],
                buy_now['address'],
                total,
                timestamp,
                payment_method
            )
        )
        receipt_db.commit()
        db.commit()

        # --- STOCK DEDUCTION ---
        if is_shoe_product(product_id):
            updated = product_db.execute(
                'UPDATE shoe_sizes SET stock = stock - ? WHERE product_id = ? AND size = ? AND stock >= ?',
                (buy_now['quantity'], product_id, buy_now['size'], buy_now['quantity'])
            )
        elif is_accessory_product(product_id) or is_equipment_product(product_id):
            updated = product_db.execute(
                'UPDATE item_stocks SET stock = stock - ? WHERE product_id = ? AND stock >= ?',
                (buy_now['quantity'], product_id, buy_now['quantity'])
            )
        else:
            updated = product_db.execute(
                'UPDATE product_sizes SET stock = stock - ? WHERE product_id = ? AND size = ? AND stock >= ?',
                (buy_now['quantity'], product_id, buy_now['size'], buy_now['quantity'])
            )
        if updated.rowcount == 0:
            flash('Stock deduction failed. Please try again.', 'danger')
            return redirect(url_for('buy_now_shipping', product_id=product_id))
        product_db.commit()

        # Clear buy_now session
        session.pop('buy_now', None)

        return render_template('confirmed.html', order_id=order_id)

    # GET request - show confirmation
    return render_template(
        'confirm_purchase.html',
        product=product,
        product_id=product_id,
        size=buy_now.get('size', ''),
        quantity=buy_now.get('quantity', 1),
        price=float(buy_now.get('price', product['price'])),
        total=float(buy_now.get('price', product['price'])) * int(buy_now.get('quantity', 1)),
        name=buy_now.get('name', ''),
        contact=buy_now.get('contact', ''),
        home_number=buy_now.get('home_number', ''),
        barangay=buy_now.get('barangay', ''),
        city=buy_now.get('city', ''),
        province=buy_now.get('province', ''),
        region=buy_now.get('region', ''),
        address=buy_now.get('address', ''),
        payment_method=buy_now.get('payment_method', ''),
        gcash_number=gcash_number,
        gcash_name=gcash_name,
        paymaya_number=paymaya_number,
        paymaya_name=paymaya_name,
        bdo_account_number=bdo_account_number,
        bdo_account_name=bdo_account_name,
        bpi_account_number=bpi_account_number,
        bpi_account_name=bpi_account_name
    )

@app.route('/buy_now_info/<product_id>', methods=['POST'])
def buy_now_info(product_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    product = get_product_by_id(product_id)
    if not product:
        flash('Product not found', 'danger')
        return redirect(url_for('home'))

    size = request.form.get('size', 'none')
    quantity = int(request.form.get('quantity', 1))
    price = float(product['price'])

    # --- Helper for Extra1-20 ---
    def is_extra_product(product_id):
        return product_id.startswith('Extra') and product_id[5:].isdigit() and 1 <= int(product_id[5:]) <= 20

    # Only require size for products that need it (apparel/shoes)
    if not (is_accessory_product(product_id) or is_equipment_product(product_id) or is_extra_product(product_id)):
        if not size or size == 'none':
            flash('Please select a size.', 'warning')
            return redirect(url_for('destination3') if product_id == "Extra23" else url_for('view_product', product_id=product_id))

    product_db = get_product_db()
    # Stock check logic
    if is_shoe_product(product_id):
        row = product_db.execute(
            'SELECT stock FROM shoe_sizes WHERE product_id = ? AND size = ?',
            (product_id, size)
        ).fetchone()
    elif is_accessory_product(product_id) or is_equipment_product(product_id) or is_extra_product(product_id):
        row = product_db.execute(
            'SELECT stock FROM item_stocks WHERE product_id = ?',
            (product_id,)
        ).fetchone()
        size = 'Standard'  # For uniformity, always use 'Standard' for Extra1-20
    else:
        row = product_db.execute(
            'SELECT stock FROM product_sizes WHERE product_id = ? AND size = ?',
            (product_id, size)
        ).fetchone()

    if not row:
        flash('Selected size not available.', 'warning')
        return redirect(url_for('destination3') if product_id == "Extra23" else url_for('view_product', product_id=product_id))
    if row['stock'] < quantity:
        flash('Insufficient stock', 'warning')
        return redirect(url_for('destination3') if product_id == "Extra23" else url_for('view_product', product_id=product_id))

    session['buy_now'] = {
        'product_id': product_id,
        'size': size,
        'quantity': quantity,
        'price': price,
        'name': '',
        'contact': '',
        'region': '',
        'province': '',
        'city': '',
        'barangay': '',
        'home_number': '',
        'address': ''
    }

    # Redirect to shipping info page, not confirm_purchase
    return redirect(url_for('buy_now_shipping', product_id=product_id))



# ==== PRODUCT ROUTES ====
@app.route('/products_db')
def view_products_db():
    search = request.args.get('search', '').strip().lower()
    products = get_all_products()
    if search:
        products = [
            p for p in products
            if search in str(p['id']).lower()
            or search in str(p['product_id']).lower()
            or search in str(p['name']).lower()
        ]
    return render_template('products_db.html', products=products)

@app.route('/product/<product_id>')
def view_product(product_id):
    # Block direct access for Extra1–Extra20
    if product_id.startswith('Extra'):
        try:
            num = int(product_id[5:])
            if 1 <= num <= 20:
                flash('Direct product detail page not available for this item.', 'warning')
                return redirect(url_for('shop1'))
        except Exception:
            pass
    product = get_product_by_id(product_id)
    if not product:
        abort(404)
    return render_template('product_detail.html', product=product)

# ==== SEARCH ROUTE ====
@app.route('/search')
def search():
    query = request.args.get('q', '').strip().lower()
    results = []
    if query:
        all_products = get_all_products()
        for product in all_products:
            if query in product['name'].lower():
                # If you want to show total stock, uncomment below (optional, not required)
                # product_db = get_product_db()
                # stock_row = product_db.execute(
                #     'SELECT SUM(stock) as total_stock FROM product_sizes WHERE product_id = ?',
                #     (product['product_id'],)
                # ).fetchone()
                # total_stock = stock_row['total_stock'] if stock_row and stock_row['total_stock'] is not None else 0
                results.append({
                    'id': product['product_id'],
                    'name': product['name'],
                    'price': product['price'],
                    'image': product['image']
                    # ,'stock': total_stock      # Optional: display total stock across all sizes
                })
    return render_template('search_results.html', query=query, results=results)

# ==== FEEDBACK SITE ======

def get_feedback_db():
    if 'feedback_db' not in g:
        g.feedback_db = sqlite3.connect('feedback.db')
        g.feedback_db.row_factory = sqlite3.Row
    return g.feedback_db


# Add to your teardown function if not already:
@app.teardown_appcontext
def close_all_dbs(error):
    # ... existing closes
    feedback_db = g.pop('feedback_db', None)
    if feedback_db is not None:
        feedback_db.close()

@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    if request.method == 'POST':
        user_email = session.get('user')
        user_id = None
        if user_email:
            db = get_db()  # <-- use your connection to users.db
            user_row = db.execute('SELECT id FROM users WHERE email = ?', (user_email,)).fetchone()
            if user_row:
                user_id = user_row['id']
        message = request.form.get('message', '').strip()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        if message:
            feedback_db = get_feedback_db()  # <-- your connection to feedback.db
            feedback_db.execute(
                "INSERT INTO web_feedback (user_id, user_email, message, created_at) VALUES (?, ?, ?, ?)",
                (user_id, user_email, message, created_at)
            )
            feedback_db.commit()
            flash('Thank you for your feedback!', 'success')
            return redirect(url_for('feedback'))
        else:
            flash('Message cannot be empty.', 'danger')
    return render_template('feedback.html')

#PRODUCT FEEDBACK ROUTES



def get_product_feedback_db():
    if 'product_feedback_db' not in g:
        g.product_feedback_db = sqlite3.connect('feedback.db')
        g.product_feedback_db.row_factory = sqlite3.Row
    return g.product_feedback_db

def get_orders():
    # Returns a list of orders from products.db for the dropdown
    conn = sqlite3.connect('products.db')
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT id, name FROM orders")
    orders = cur.fetchall()
    conn.close()
    return orders

@app.teardown_appcontext
def close_product_feedback_db(error):
    db = g.pop('product_feedback_db', None)
    if db is not None:
        db.close()

# Payemnt method
@app.route('/checkout/success')
def checkout_success():
    # You can pass order_id and payment_method as needed, or remove if not used
    order_id = request.args.get('order_id', 'N/A')
    payment_method = request.args.get('payment_method', 'N/A')
    return render_template('checkout_success.html', order_id=order_id, payment_method=payment_method)

@app.route('/checkout/gcash', methods=['GET', 'POST'])
def gcash_details():
    if 'user' not in session or 'pending_checkout' not in session:
        return redirect(url_for('checkout'))
    if request.method == 'POST':
        gcash_number = request.form.get("gcash_number", "").strip()
        gcash_name = request.form.get("gcash_name", "").strip()
        checkout_data = session.pop('pending_checkout')
        db = get_receipt_db()  # <--- use receipt.db!
        cart = get_cart(session['user'])
        total = sum(item['price'] * item['quantity'] for item in cart)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        order_id = f"{session['user']}-{int(datetime.now().timestamp())}"
        user_email = session['user']
        address = checkout_data['address']
        db.execute(
            "INSERT INTO receipts (order_id, user_email, name, contact, address, total, timestamp, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (order_id, user_email, checkout_data['name'], checkout_data['contact'], address, total, timestamp, "GCash")
        )
        db.commit()
        clear_cart(session['user'])
        return render_template('checkout_success.html', order_id=order_id, payment_method="GCash")
    return render_template('gcash.html')
# PayMaya details page
@app.route('/checkout/paymaya', methods=['GET', 'POST'])
def paymaya_details():
    if 'user' not in session or 'pending_checkout' not in session:
        return redirect(url_for('checkout'))
    if request.method == 'POST':
        paymaya_number = request.form.get("paymaya_number", "").strip()
        paymaya_name = request.form.get("paymaya_name", "").strip()
        checkout_data = session.pop('pending_checkout')
        db = get_receipt_db()  # <--- use receipt.db!
        cart = get_cart(session['user'])
        total = sum(item['price'] * item['quantity'] for item in cart)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        order_id = f"{session['user']}-{int(datetime.now().timestamp())}"
        user_email = session['user']
        address = checkout_data['address']
        db.execute(
            "INSERT INTO receipts (order_id, user_email, name, contact, address, total, timestamp, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (order_id, user_email, checkout_data['name'], checkout_data['contact'], address, total, timestamp, "PayMaya")
        )
        db.commit()
        clear_cart(session['user'])
        # You may want to save paymaya_number/paymaya_name to another table or log them for reference.
        return render_template('checkout_success.html', order_id=order_id, payment_method="PayMaya")
    return render_template('paymaya.html')

@app.route('/checkout/bdo', methods=['GET', 'POST'])
def bdo_details():
    if 'user' not in session or 'pending_checkout' not in session:
        return redirect(url_for('checkout'))
    if request.method == 'POST':
        bdo_account_number = request.form.get("bdo_account_number", "").strip()
        bdo_account_name = request.form.get("bdo_account_name", "").strip()
        checkout_data = session.pop('pending_checkout')
        db = get_receipt_db()  # <--- use receipt.db!
        cart = get_cart(session['user'])
        total = sum(item['price'] * item['quantity'] for item in cart)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        order_id = f"{session['user']}-{int(datetime.now().timestamp())}"
        user_email = session['user']
        address = checkout_data['address']
        db.execute(
            "INSERT INTO receipts (order_id, user_email, name, contact, address, total, timestamp, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (order_id, user_email, checkout_data['name'], checkout_data['contact'], address, total, timestamp, "BDO")
        )
        db.commit()
        clear_cart(session['user'])
        # You may want to save bdo_account_number/bdo_account_name to another table or log them for reference.
        return render_template('checkout_success.html', order_id=order_id, payment_method="BDO")
    return render_template('bdo.html')

# BPI details page
@app.route('/checkout/bpi', methods=['GET', 'POST'])
def bpi_details():
    if 'user' not in session or 'pending_checkout' not in session:
        return redirect(url_for('checkout'))
    if request.method == 'POST':
        bpi_account_number = request.form.get("bpi_account_number", "").strip()
        bpi_account_name = request.form.get("bpi_account_name", "").strip()
        checkout_data = session.pop('pending_checkout')
        db = get_receipt_db()  # <--- use receipt.db!
        cart = get_cart(session['user'])
        total = sum(item['price'] * item['quantity'] for item in cart)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        order_id = f"{session['user']}-{int(datetime.now().timestamp())}"
        user_email = session['user']
        address = checkout_data['address']
        db.execute(
            "INSERT INTO receipts (order_id, user_email, name, contact, address, total, timestamp, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (order_id, user_email, checkout_data['name'], checkout_data['contact'], address, total, timestamp, "BPI")
        )
        db.commit()
        clear_cart(session['user'])
        # You may want to save bpi_account_number/bpi_account_name to another table or log them for reference.
        return render_template('checkout_success.html', order_id=order_id, payment_method="BPI")
    return render_template('bpi.html')


   # --- Check stock before placing order ---
    for item in cart:
        row = product_db.execute(
            'SELECT stock FROM products WHERE product_id = ?', (item['product_id'],)
        ).fetchone()
        if not row or row['stock'] < item['quantity']:
            flash(f"Not enough stock for {item['name']}! Only {row['stock']} left.", "danger")
            # REDIRECT TO STATIC PAGE IF DEFINED, ELSE CART
            route = PRODUCT_ID_TO_ROUTE.get(item['product_id'])
            if route:
                return redirect(route)
            else:
                return redirect(url_for('view_cart'))

    # --- Place the order ---
    cur = db.execute('INSERT INTO orders (user_email, timestamp, name, contact, address, total_amount) VALUES (?, ?, ?, ?, ?, ?)',
                     (session['user'], timestamp, name, contact, address, total))
    order_id = cur.lastrowid
    for item in cart:
        db.execute('INSERT INTO order_items (order_id, product_id, name, size, quantity, price, image) VALUES (?, ?, ?, ?, ?, ?, ?)',
                   (order_id, item['product_id'], item['name'], item['size'], item['quantity'], item['price'], item['image']))
    db.commit()


# ---- ADMIN FEEDBACK VIEW ----

@app.route('/admin/product_feedback')
def admin_product_feedback():
    db = get_product_feedback_db()
    feedback_list = db.execute(
        'SELECT order_id, user, rating, comment, submitted_at FROM product_feedback ORDER BY submitted_at DESC'
    ).fetchall()
    return render_template('admin_product_feedback.html', feedback_list=feedback_list)

# ---- PRODUCT FEEDBACK ROUTES ----

@app.route('/product_feedback', methods=['GET', 'POST'])
def product_feedback():
    if "user" not in session:
        return redirect(url_for("login"))

    db = get_feedback_db()  # Use the correct feedback DB connection

    if request.method == 'POST':
        order_id = request.form.get('order_id')
        user = session.get('user')
        rating = request.form.get('rating')
        comment = request.form.get('comment')
        submitted_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if not order_id:
            return "Order ID is required!", 400

        db.execute(
            'INSERT INTO product_feedback (order_id, user, rating, comment, submitted_at) VALUES (?, ?, ?, ?, ?)',
            (order_id, user, rating, comment, submitted_at)
        )
        db.commit()
        return redirect(url_for('dashboard'))  # Or a thank you/confirmation page if you prefer

    else:
        # Only fetch orders for this user that are marked as delivered
        user = session.get('user')
        # Assuming orders are still in products.db; keep get_db() for orders
        orders_db = get_db()
        orders = orders_db.execute(
            "SELECT * FROM orders WHERE user_email=? AND status='Delivered'", (user,)
        ).fetchall()
        return render_template('product_feedback.html', orders=orders)


# ---- SET DELIVERED ROUTE (unchanged) ----
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect('products.db')
        g.db.row_factory = sqlite3.Row
    return g.db

@app.route('/set_delivered/<int:order_id>', methods=['POST'])
def set_delivered(order_id):
    db = get_db()  # Use the same DB connection function everywhere
    db.execute('UPDATE orders SET status = ? WHERE id = ?', ('Delivered', order_id))
    db.commit()
    return redirect(url_for('dashboard'))

@app.route('/admin/feedback')
@admin_required
def admin_feedback():
    db = get_feedback_db()
    all_feedback = db.execute('SELECT * FROM web_feedback ORDER BY created_at DESC').fetchall()
    return render_template('admin_feedback.html', feedbacks=all_feedback)

# ==== GENERAL STATIC PAGES ====
@app.route('/')
def home():
    cart_count = get_cart_count(session['user']) if 'user' in session else 0
    return render_template('main.html', cart_count=cart_count)

@app.route('/contact')
def contact():
    return render_template("contact.html")
@app.route('/about')
def about():
    return render_template('about.html')
@app.route('/termsandcondition')
def termsandcondition():
    return render_template('termsandcondition.html')
@app.route('/privacy')
def privacy():
    return render_template('privacy.html')
@app.route('/orderandship')
def orderandship():
    return render_template('orderandship.html')
@app.route('/sizechart')
def sizechart():
    return render_template('sizechart.html')
@app.route('/giftcard')
def giftcard():
    return render_template('giftcard.html')
@app.route('/loyalty')
def loyalty():
    return render_template('loyalty.html')
@app.route('/main')
def main():
    return render_template('main.html')
@app.route("/manage_item_stock/<product_id>", methods=["GET", "POST"])
def manage_item_stock(product_id):
    # Allow Extra1–Extra20, accessories, and equipments (do not affect anything else)
    allowed_ids = {f"Extra{i}" for i in range(1, 21)}
    if not (
        product_id in allowed_ids
        or product_id.startswith("accessories")
        or product_id.startswith("equipments")
    ):
        flash("Unknown product type.", "danger")
        return render_template("manage_item_stock.html", product_id=product_id, stock=0)

    db = get_product_db()
    cur = db.cursor()
    cur.execute("SELECT stock FROM item_stocks WHERE product_id = ?", (product_id,))
    row = cur.fetchone()
    current_stock = row["stock"] if row else 0

    if request.method == "POST":
        action = request.form.get("action")
        value = int(request.form.get("stock", 0))
        if action == "set":
            cur.execute("UPDATE item_stocks SET stock = ? WHERE product_id = ?", (value, product_id))
        elif action == "add":
            cur.execute("UPDATE item_stocks SET stock = stock + ? WHERE product_id = ?", (value, product_id))
        db.commit()
        # re-query after update
        cur.execute("SELECT stock FROM item_stocks WHERE product_id = ?", (product_id,))
        row = cur.fetchone()
        current_stock = row["stock"] if row else 0
        flash("Stock updated.", "success")

    cur.close()
    return render_template("manage_item_stock.html", product_id=product_id, stock=current_stock)
# ==== Sizes ====
@app.route("/manage_sizes/<product_id>")
def manage_sizes(product_id):
    db = get_product_db()
    cur = db.cursor()
    cur.execute("SELECT * FROM product_sizes WHERE product_id = ?", (product_id,))
    sizes = cur.fetchall()
    cur.close()
    return render_template("manage_sizes.html", product_id=product_id, sizes=sizes)
@app.route("/manage_stock/<product_id>")
def manage_stock(product_id):
    # Shoes1-9 should be managed via shoe_sizes
    if product_id in [f"shoes{i}" for i in range(1, 10)]:
        return redirect(url_for("manage_shoe_sizes", product_id=product_id))
    # Define your product type logic based on product_id prefix
    if product_id.startswith(("top", "bottoms", "compressions", "dresses", "compression", "terno")):
        # All these are clothing: send to manage_sizes
        return redirect(url_for("manage_sizes", product_id=product_id))
    # If you add shoes, accessories, or equipment, add checks here
    # Example for shoes:
    # elif product_id.startswith("shoes"):
    #     return redirect(url_for("manage_shoe_sizes", product_id=product_id))
    # Example for accessories/equipment:
    elif product_id.startswith(("accessories", "equipments")):
        return redirect(url_for("manage_item_stock", product_id=product_id))
    else:
        return "Unknown product type.", 400


@app.route("/manage_shoe_sizes/<product_id>")
def manage_shoe_sizes(product_id):
    db = get_product_db()
    cur = db.cursor()
    # Only allow shoe products: e.g., those starting with "shoes" or Extra21/Extra22
    allowed_ids = {"Extra21", "Extra22"}
    is_shoe = product_id.startswith("shoes") or product_id in allowed_ids
    if not is_shoe:
        flash("Unknown shoe product.", "danger")
        cur.close()
        return render_template("manage_shoe_sizes.html", product_id=product_id, sizes=[])

    cur.execute("SELECT * FROM shoe_sizes WHERE product_id = ?", (product_id,))
    sizes = cur.fetchall()
    cur.close()
    return render_template("manage_shoe_sizes.html", product_id=product_id, sizes=sizes)


@app.route("/update_size_stock/<int:size_id>", methods=["POST"])
def update_size_stock(size_id):
    new_stock = request.form.get("stock")
    db = get_product_db()
    cur = db.cursor()
    cur.execute("UPDATE product_sizes SET stock = ? WHERE id = ?", (new_stock, size_id))
    db.commit()
    cur.execute("SELECT product_id FROM product_sizes WHERE id = ?", (size_id,))
    product_id = cur.fetchone()[0]
    cur.close()
    return redirect(url_for("manage_sizes", product_id=product_id))

@app.route('/product/<product_id>')
def product_page(product_id):
    # Query product info and whether it has sizes
    product = get_product_by_id(product_id)
    # Example: for Extra1-20, has_sizes = False
    has_sizes = product['category'] in ['Shirt', 'Shoes']  # or however you classify
    # Or:
    if product_id.startswith('Extra') and 1 <= int(product_id[5:]) <= 20:
        has_sizes = False
    # ...rest of your logic...
    return render_template('product.html', product=product, has_sizes=has_sizes)

@app.route("/product_detail/<product_id>")
def product_detail(product_id):
    conn = sqlite3.connect("products.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM products WHERE product_id = ?", (product_id,))
    product = cur.fetchone()

    # Get all sizes and stock for this product
    cur.execute("SELECT size, stock FROM product_sizes WHERE product_id = ?", (product_id,))
    sizes = cur.fetchall()

    conn.close()

    # Convert to dictionary: { "XS": 3, "S": 2, ... }
    size_stock_map = {row["size"]: row["stock"] for row in sizes}

    return render_template("product_detail.html", product=product, size_stock=size_stock_map)


# === manage shoes size ===


def get_shoe_products():
    conn = sqlite3.connect("products.db")
    c = conn.cursor()
    c.execute("SELECT id, product_id, name, price, image FROM products WHERE product_id LIKE 'shoes%' OR product_id LIKE 'destination%'")
    products = c.fetchall()
    conn.close()
    # products: (id, product_id, name, price, image)
    return products

def get_shoe_sizes(product_id):
    conn = sqlite3.connect("products.db")
    c = conn.cursor()
    c.execute("SELECT size, stock FROM shoe_sizes WHERE product_id = ? ORDER BY size", (product_id,))
    sizes = c.fetchall()
    conn.close()
    # sizes: (size, stock)
    return sizes

def update_shoe_size_stock(product_id, size, new_stock):
    conn = sqlite3.connect("products.db")
    c = conn.cursor()
    c.execute("UPDATE shoe_sizes SET stock = ? WHERE product_id = ? AND size = ?", (new_stock, product_id, size))
    conn.commit()
    conn.close()

@app.route("/manage_shoes")
def manage_shoes():
    db = get_product_db()
    cur = db.cursor()
    cur.execute("SELECT id, product_id, name, price, image FROM products WHERE product_id LIKE 'shoes%' OR product_id LIKE 'destination%'")
    products = cur.fetchall()
    cur.close()
    return render_template("manage_shoes.html", products=products)

@app.route("/women")
def women(): return render_template("women/women.html")

@app.route("/women/top")
def top_women(): return render_template("women/tops/top_women.html")

@app.route("/women/bottoms")
def bottoms_women(): return render_template("women/bottoms/bottoms_women.html")

@app.route("/women/compressions")
def compressions_women(): return render_template("women/compressions/compressions_women.html")

@app.route("/women/dresses")
def dresses_women(): return render_template("women/dresses/dresses_women.html")

@app.route("/men")
def men(): return render_template("men/men.html")

@app.route("/men/tops")
def top_men(): return render_template("men/tops/top_men.html")

@app.route("/men/bottom")
def bottom_men(): return render_template("men/bottoms/bottom_men.html")

@app.route("/men/compression")
def compression_men(): return render_template("men/compression/compression_men.html")

@app.route("/men/terno")
def terno_men(): return render_template("men/terno/terno_men.html")

def render_sized_product(product_id, template_path):
    conn = sqlite3.connect("products.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    product = get_product_by_id(product_id)

    cur.execute("SELECT size, stock FROM product_sizes WHERE product_id = ?", (product_id,))
    sizes = cur.fetchall()
    conn.close()

    size_stock = {row["size"]: row["stock"] for row in sizes}

    return render_template(template_path, product=product, size_stock=size_stock)

# WOMEN TOPS
@app.route("/women/top/top1")
def top1_women(): return render_sized_product("top1_women", "women/tops/top1_women.html")

@app.route("/women/top/top2")
def top2_women(): return render_sized_product("top2_women", "women/tops/top2_women.html")

@app.route("/women/top/top3")
def top3_women(): return render_sized_product("top3_women", "women/tops/top3_women.html")

@app.route("/women/top/top4")
def top4_women(): return render_sized_product("top4_women", "women/tops/top4_women.html")

# WOMEN BOTTOMS
@app.route("/women/bottoms/bottoms1")
def bottoms1_women(): return render_sized_product("bottoms1_women", "women/bottoms/bottoms1_women.html")

@app.route("/women/bottoms/bottoms2")
def bottoms2_women(): return render_sized_product("bottoms2_women", "women/bottoms/bottoms2_women.html")

@app.route("/women/bottoms/bottoms3")
def bottoms3_women(): return render_sized_product("bottoms3_women", "women/bottoms/bottoms3_women.html")

@app.route("/women/bottoms/bottoms4")
def bottoms4_women(): return render_sized_product("bottoms4_women", "women/bottoms/bottoms4_women.html")

# WOMEN COMPRESSIONS
@app.route("/women/compressions/compressions1")
def compressions1_women(): return render_sized_product("compressions1_women", "women/compressions/compressions1_women.html")

@app.route("/women/compressions/compressions2")
def compressions2_women(): return render_sized_product("compressions2_women", "women/compressions/compressions2_women.html")

@app.route("/women/compressions/compressions3")
def compressions3_women(): return render_sized_product("compressions3_women", "women/compressions/compressions3_women.html")

@app.route("/women/compressions/compressions4")
def compressions4_women(): return render_sized_product("compressions4_women", "women/compressions/compressions4_women.html")

# WOMEN DRESSES
@app.route("/women/dresses/dresses1")
def dresses1_women(): return render_sized_product("dresses1_women", "women/dresses/dresses1_women.html")

@app.route("/women/dresses/dresses2")
def dresses2_women(): return render_sized_product("dresses2_women", "women/dresses/dresses2_women.html")

@app.route("/women/dresses/dresses3")
def dresses3_women(): return render_sized_product("dresses3_women", "women/dresses/dresses3_women.html")

@app.route("/women/dresses/dresses4")
def dresses4_women(): return render_sized_product("dresses4_women", "women/dresses/dresses4_women.html")

# MEN TOPS
@app.route("/men/tops/top1")
def top1_men(): return render_sized_product("top1_men", "men/tops/top1_men.html")

@app.route("/men/tops/top2")
def top2_men(): return render_sized_product("top2_men", "men/tops/top2_men.html")

@app.route("/men/tops/top3")
def top3_men(): return render_sized_product("top3_men", "men/tops/top3_men.html")

@app.route("/men/tops/top4")
def top4_men(): return render_sized_product("top4_men", "men/tops/top4_men.html")

# MEN BOTTOMS
@app.route("/men/bottom/bottom1")
def bottom1_men(): return render_sized_product("bottom1_men", "men/bottoms/bottom1_men.html")

@app.route("/men/bottom/bottom2")
def bottom2_men(): return render_sized_product("bottom2_men", "men/bottoms/bottom2_men.html")

@app.route("/men/bottom/bottom3")
def bottom3_men(): return render_sized_product("bottom3_men", "men/bottoms/bottom3_men.html")

@app.route("/men/bottom/bottom4")
def bottom4_men(): return render_sized_product("bottom4_men", "men/bottoms/bottom4_men.html")

# MEN COMPRESSION
@app.route("/men/compression/compression1")
def compression1_men(): return render_sized_product("compression1_men", "men/compression/compression1_men.html")

@app.route("/men/compression/compression2")
def compression2_men(): return render_sized_product("compression2_men", "men/compression/compression2_men.html")

@app.route("/men/compression/compression3")
def compression3_men(): return render_sized_product("compression3_men", "men/compression/compression3_men.html")

@app.route("/men/compression/compression4")
def compression4_men(): return render_sized_product("compression4_men", "men/compression/compression4_men.html")

# MEN TERNO
@app.route("/men/terno/terno1")
def terno1_men(): return render_sized_product("terno1_men", "men/terno/terno1_men.html")

@app.route("/men/terno/terno2")
def terno2_men(): return render_sized_product("terno2_men", "men/terno/terno2_men.html")

@app.route("/men/terno/terno3")
def terno3_men(): return render_sized_product("terno3_men", "men/terno/terno3_men.html")

@app.route("/men/terno/terno4")
def terno4_men(): return render_sized_product("terno4_men", "men/terno/terno4_men.html")

# Helper function for accessory/equipment detail routes
def render_accessory_or_equipment(product_id, template_path):
    product = get_product_by_id(product_id)
    # Get stock from item_stocks
    conn = sqlite3.connect("products.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT stock FROM item_stocks WHERE product_id = ?", (product_id,))
    row = cur.fetchone()
    stock = row["stock"] if row else 0
    conn.close()
    return render_template(template_path, product=product, stock=stock)

@app.route("/accessories_and_equipments/")
def accessories_and_equipments():
    return render_template("accessories_and_equipments/accessories_and_equipments.html")

@app.route("/accessories_and_equipments/accessories")
def accessories():
    return render_template("accessories_and_equipments/accessories/accessories.html")

@app.route("/accessories_and_equipments/accessories/accessories1")
def accessories1():
    return render_accessory_or_equipment("accessories1", "accessories_and_equipments/accessories/accessories1.html")

@app.route("/accessories_and_equipments/accessories/accessories2")
def accessories2():
    return render_accessory_or_equipment("accessories2", "accessories_and_equipments/accessories/accessories2.html")

@app.route("/accessories_and_equipments/accessories/accessories3")
def accessories3():
    return render_accessory_or_equipment("accessories3", "accessories_and_equipments/accessories/accessories3.html")

@app.route("/accessories_and_equipments/accessories/accessories4")
def accessories4():
    return render_accessory_or_equipment("accessories4", "accessories_and_equipments/accessories/accessories4.html")

def is_equipment_product(product_id):
    return product_id.startswith('equipments')

@app.route("/accessories_and_equipments/equipments")
def equipments():
    # Render an equipment list page (create this template)
    return render_template("accessories_and_equipments/equipments/equipments.html")

@app.route("/accessories_and_equipments/equipments/equipments1")
def equipments1():
    return render_accessory_or_equipment("equipments1", "accessories_and_equipments/equipments/equipments1.html")

@app.route("/accessories_and_equipments/equipments/equipments2")
def equipments2():
    return render_accessory_or_equipment("equipments2", "accessories_and_equipments/equipments/equipments2.html")

@app.route("/accessories_and_equipments/equipments/equipments3")
def equipments3():
    return render_accessory_or_equipment("equipments3", "accessories_and_equipments/equipments/equipments3.html")

@app.route("/accessories_and_equipments/equipments/equipments4")
def equipments4():
    return render_accessory_or_equipment("equipments4", "accessories_and_equipments/equipments/equipments4.html")

def render_extra_product(product_id, template_path):
    product = get_product_by_id(product_id)
    # Get stock from item_stocks
    conn = sqlite3.connect("products.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT stock FROM item_stocks WHERE product_id = ?", (product_id,))
    row = cur.fetchone()
    stock = row["stock"] if row else 0
    conn.close()
    return render_template(template_path, product=product, stock=stock)

@app.route("/shop1")
def shop1():
    extra_ids = [f"Extra{i}" for i in range(1, 21)]
    conn = sqlite3.connect("products.db")
    cur = conn.cursor()
    cur.execute(
        "SELECT product_id, stock FROM item_stocks WHERE product_id IN ({})".format(
            ",".join("?" for _ in extra_ids)
        ),
        extra_ids
    )
    stocks = dict(cur.fetchall())
    conn.close()
    return render_template("shop1.html", stocks=stocks)


@app.route("/update_shoe_size_stock/<int:size_id>", methods=["POST"])
def update_shoe_size_stock(size_id):
    new_stock = request.form.get("stock")
    db = get_product_db()
    cur = db.cursor()
    cur.execute("UPDATE shoe_sizes SET stock = ? WHERE id = ?", (new_stock, size_id))
    db.commit()
    cur.execute("SELECT product_id FROM shoe_sizes WHERE id = ?", (size_id,))
    product_id = cur.fetchone()[0]
    cur.close()
    return redirect(url_for("manage_shoe_sizes", product_id=product_id))

@app.route("/shoes")
def shoes(): return render_template("shoes/shoes.html")
import sqlite3

def render_shoe_product(product_id, template_path):
    conn = sqlite3.connect("products.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    # If you have product info function, keep this; else remove
    try:
        product = get_product_by_id(product_id)
    except Exception:
        product = None

    # Adjust the table name if you use product_sizes for all
    cur.execute("SELECT size, stock FROM shoe_sizes WHERE product_id = ?", (product_id,))
    sizes = cur.fetchall()
    conn.close()

    # Always provide size_stock, even if empty
    size_stock = {row["size"]: row["stock"] for row in sizes}

    return render_template(template_path, product=product, size_stock=size_stock)

@app.route("/shoes/shoes1")
def shoes1():
    return render_shoe_product("shoes1", "shoes/shoes1.html")

@app.route("/shoes/shoes2")
def shoes2():
    return render_shoe_product("shoes2", "shoes/shoes2.html")

@app.route("/shoes/shoes3")
def shoes3():
    return render_shoe_product("shoes3", "shoes/shoes3.html")

@app.route("/shoes/shoes4")
def shoes4():
    return render_shoe_product("shoes4", "shoes/shoes4.html")

@app.route("/shoes/shoes5")
def shoes5():
    return render_shoe_product("shoes5", "shoes/shoes5.html")

@app.route("/shoes/shoes6")
def shoes6():
    return render_shoe_product("shoes6", "shoes/shoes6.html")

@app.route("/shoes/shoes7")
def shoes7():
    return render_shoe_product("shoes7", "shoes/shoes7.html")

@app.route("/shoes/shoes8")
def shoes8():
    return render_shoe_product("shoes8", "shoes/shoes8.html")

@app.route("/shoes/shoes9")
def shoes9():
    return render_shoe_product("shoes9", "shoes/shoes9.html")

@app.route("/shop1/extra<int:num>")
def render_extra(num):
    product_id = f"Extra{num}"
    template_path = f"shop1/extra{num}.html"
    return render_accessory_or_equipment(product_id, template_path)


DATABASE = 'products.db'

def get_product_db():
    if 'product_db' not in g:
        g.product_db = sqlite3.connect(DATABASE)
        g.product_db.row_factory = sqlite3.Row
    return g.product_db


def check_extra_stocks():
    conn = sqlite3.connect('products.db')
    cur = conn.cursor()
    for i in range(1, 21):
        product_id = f"Extra{i}"
        cur.execute("SELECT stock FROM item_stocks WHERE product_id = ?", (product_id,))
        row = cur.fetchone()
        print(f"{product_id}: {row['stock'] if row else 'Not found'}")
    conn.close()

def initialize_extra_stocks():
    conn = sqlite3.connect('products.db')
    cur = conn.cursor()
    for i in range(1, 21):
        product_id = f"Extra{i}"
        # Check if stock entry exists
        cur.execute("SELECT 1 FROM item_stocks WHERE product_id = ?", (product_id,))
        if not cur.fetchone():
            # Insert with default stock of 100
            cur.execute("INSERT INTO item_stocks (product_id, stock) VALUES (?, ?)", 
                       (product_id, 100))
    conn.commit()
    conn.close()

def check_stock(product_id, size):
    product_db = get_product_db()
    if is_shoe_product(product_id):
        row = product_db.execute(
            'SELECT stock FROM shoe_sizes WHERE product_id = ? AND size = ?',
            (product_id, size)
        ).fetchone()
    else:
        row = product_db.execute(
            'SELECT stock FROM product_sizes WHERE product_id = ? AND size = ?',
            (product_id, size)
        ).fetchone()
    return row


@app.route("/destination1")
def destination1():
    return render_shoe_product("Extra21", "destination1.html")


@app.route("/destination2")
def destination2():
    return render_shoe_product("Extra22", "destination2.html")

@app.teardown_appcontext
def close_connection(exception):
    db = g.pop('product_db', None)
    if db is not None:
        db.close()

def get_product_size_stock(product_id):
    conn = sqlite3.connect("products.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT size, stock FROM product_sizes WHERE product_id = ?", (product_id,))
    sizes = cur.fetchall()
    conn.close()
    return {row["size"]: row["stock"] for row in sizes}

@app.route("/destination3")
def destination3():
    import sqlite3
    conn = sqlite3.connect("products.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    # Get all size/stock for Extra23 from product_sizes
    cur.execute("SELECT size, stock FROM product_sizes WHERE product_id = ?", ("Extra23",))
    sizes = cur.fetchall()
    conn.close()
    size_stock = {row["size"]: row["stock"] for row in sizes}
    return render_template("destination3.html", size_stock=size_stock)


# --- Add this helper function near your other DB helpers ---
def get_receipt_db():
    if 'receipt_db' not in g:
        g.receipt_db = sqlite3.connect('receipt.db')
        g.receipt_db.row_factory = sqlite3.Row
    return g.receipt_db

@app.teardown_appcontext
def close_receipt_db(error):
    db = g.pop('receipt_db', None)
    if db is not None:
        db.close()

def save_receipt(
    order_id,
    user_email,
    name,
    contact,
    address,
    total,
    items_list,
    payment_method=None
):
    receipt_db = get_receipt_db()
    from datetime import datetime
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    # Insert into receipts with payment_method only
    receipt_cur = receipt_db.execute(
        '''
        INSERT INTO receipts (
            order_id, user_email, name, contact, address, total, timestamp, payment_method
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (
            order_id, user_email, name, contact, address, total, timestamp, payment_method
        )
    )
    receipt_id = receipt_cur.lastrowid

    for item in items_list:
        subtotal = item['price'] * item['quantity']
        receipt_db.execute(
            'INSERT INTO receipt_items (receipt_id, product_id, name, quantity, price, subtotal) VALUES (?, ?, ?, ?, ?, ?)',
            (receipt_id, item['product_id'], item['name'], item['quantity'], item['price'], subtotal)
        )
    receipt_db.commit()
    
if __name__ == "__main__":
    with app.app_context():
        setup()        # Creates old sqlite3 tables
        db.create_all()  # <-- Add this line to create SQLAlchemy tables!
    app.run(host='0.0.0.0', port=5000, debug=True)