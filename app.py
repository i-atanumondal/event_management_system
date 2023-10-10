from flask import Flask, render_template, request, redirect, url_for, session, flash,jsonify
import mysql.connector
import bcrypt

app = Flask(__name__)
app.secret_key = 'atanu#####secret_key#######mondal' 

db_config = {
    "host": "localhost",
    "user": "root",
    "password": "root",
    "database": "event_management",
}

db = mysql.connector.connect(**db_config)

cursor = db.cursor()

@app.route('/admin/signup', methods=['GET', 'POST'])
def admin_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        category = request.form['category']

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor.execute(
                "INSERT INTO admins (name, email, password, category) VALUES (%s, %s, %s, %s)",
                (name, email, hashed_password, category)
            )
            db.commit()

            flash('Admin registered successfully', 'success')
            return redirect(url_for('admin_login'))
        except mysql.connector.Error as err:
            db.rollback()
            flash(f"Error: {err}", 'danger')

    return render_template('admin/signup.html')

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        cursor.execute("SELECT * FROM admins WHERE email = %s", (email,))
        admin = cursor.fetchone()

        if admin and bcrypt.checkpw(password.encode('utf-8'), admin[3].encode('utf-8')):
            session['admin_id'] = admin[0]
            flash('Login successful', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    return render_template('admin/login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin/dashboard.html')
@app.route('/user/signup', methods=['GET', 'POST'])
def user_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            flash('Email address already exists. Please choose another email.', 'danger')
        else:
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            try:
                cursor.execute(
                    "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                    (name, email, hashed_password)
                )
                db.commit()
                flash('User registered successfully', 'success')
                return redirect(url_for('user_login'))
            except mysql.connector.Error as err:
                db.rollback()
                flash(f"Error: {err}", 'danger')

    return render_template('user/signup.html')


@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[3].encode('utf-8')):
            session['user_id'] = user[0]
            flash('Login successful', 'success')
            return redirect(url_for('user_dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')
            cursor.execute("INSERT INTO canceled_logins (email) VALUES (%s)", (email,))
            db.commit()

    return render_template('user/login.html')




@app.route('/vendor/signup', methods=['GET', 'POST'])
def vendor_signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        category = request.form['category']
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor.execute(
                "INSERT INTO vendors (name, email, password, category) VALUES (%s, %s, %s, %s)",
                (name, email, hashed_password, category)
            )
            db.commit()

            flash('Vendor registered successfully', 'success')
            return redirect(url_for('vendor_login'))
        except mysql.connector.Error as err:
            db.rollback()
            flash(f"Error: {err}", 'danger')

    return render_template('vendor/signup.html')


@app.route('/vendor/login', methods=['GET', 'POST'])
def vendor_login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        cursor.execute("SELECT * FROM vendors WHERE email = %s", (email,))
        vendor = cursor.fetchone()

        if vendor and bcrypt.checkpw(password.encode('utf-8'), vendor[3].encode('utf-8')):
            session['vendor_id'] = vendor[0]
            flash('Login successful', 'success')
            return redirect(url_for('vendor_dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    return render_template('vendor/login.html')

def get_logged_in_vendor_id():
    return session.get('vendor_id')


@app.route('/vendor/dashboard')
def vendor_dashboard():
    vendor_id = get_logged_in_vendor_id()

    cursor.execute("SELECT name FROM vendors WHERE id = %s", (vendor_id,))
    vendor_name = cursor.fetchone()[0]  

    cursor.execute("SELECT * FROM vendor_items WHERE vendor_id = %s", (vendor_id,))
    items = cursor.fetchall()

    return render_template('vendor/dashboard.html', vendor_name=vendor_name, items=items)


@app.route('/vendor/items')
def vendor_items():
    vendor_id = session.get('vendor_id')
    if vendor_id is None:
        return redirect(url_for('vendor_login'))
    cursor.execute("SELECT id, name, description, price FROM vendor_items WHERE vendor_id = %s", (vendor_id,))
    items = cursor.fetchall()

    return render_template('vendor/items.html', items=items)

@app.route('/vendor/add-item', methods=['GET', 'POST'])
def vendor_add_item():
    if request.method == 'POST':
        name = request.form['name']
        description = request.form['description']
        price = float(request.form['price']) 
        vendor_id = session.get('vendor_id')
        if vendor_id is None:
            return redirect(url_for('vendor_login'))

        cursor.execute(
            "INSERT INTO vendor_items (vendor_id, name, description, price) VALUES (%s, %s, %s, %s)",
            (vendor_id, name, description, price)
        )
        db.commit()
        return redirect(url_for('vendor_items'))

    return render_template('vendor/add_item.html')

@app.route('/vendor/delete-item/<int:item_id>', methods=['POST'])
def vendor_delete_item(item_id):
    if 'vendor_id' not in session:
        flash('Please log in to perform this action.', 'danger')
        return redirect(url_for('vendor_login'))

    vendor_id = session['vendor_id']

    try:
        cursor.execute("SELECT * FROM vendor_items WHERE id = %s AND vendor_id = %s", (item_id, vendor_id))
        item = cursor.fetchone()

        if item:
            cursor.execute("DELETE FROM vendor_items WHERE id = %s", (item_id,))
            db.commit()
            flash('Item deleted successfully', 'success')
        else:
            flash('Item not found or you do not have permission to delete it', 'danger')

    except mysql.connector.Error as err:
        db.rollback()
        flash(f"Error: {err}", 'danger')

    return redirect(url_for('vendor_your_items'))
@app.route('/vendor/logout', methods=['POST'])
def vendor_logout():
    session.pop('vendor_id', None) 
    flash('Vendor logged out successfully', 'success')
    return redirect(url_for('vendor_login'))



@app.route('/user/dashboard')
def user_dashboard():
    user_name = session.get('user_name')
    selected_vendor_type = session.get('selected_vendor_type')

    return render_template('user/dashboard.html', user_name=user_name, selected_vendor_type=selected_vendor_type)


@app.route('/user/vendors', methods=['GET'])
def display_vendor_categories():
    vendor_categories = ['Catering', 'Florist', 'Decoration', 'Lighting']
    return render_template('user/vendor_categories.html', vendor_categories=vendor_categories)

def get_vendors_in_category(category):
    try:
        cursor.execute("SELECT * FROM vendors WHERE category = %s", (category,))
        vendors = cursor.fetchall()
        return vendors
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []
    
    
@app.route('/user/vendors/<category>')
def vendors_in_category(category):
    vendors = get_vendors_in_category(category)
    return render_template('user/vendors_in_category.html', category=category, vendors=vendors)
@app.route('/user/vendors/<category>', methods=['GET'])
def display_vendors_in_category(category):
    vendors = get_vendors_in_category(category) 

    return render_template('user/vendors_by_category.html', category=category, vendors=vendors)

def get_vendor_items(vendor_id):
    try:
        cursor.execute("SELECT * FROM vendor_items WHERE vendor_id = %s", (vendor_id,))
        items = cursor.fetchall()
        return items
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []

@app.route('/user/shop-items/<vendor_id>', methods=['GET'])
def shop_items(vendor_id):
    vendor_items = get_vendor_items(vendor_id)  

    return render_template('user/shop_items.html', vendor_items=vendor_items)


if __name__ == '__main__':
    app.run(port= 6060,debug=True)