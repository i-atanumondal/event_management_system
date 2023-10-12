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
@app.route('/')
def landing_page():
    return render_template('landing.html')

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

    return redirect(url_for('vendor_items'))

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
        cursor.execute("SELECT id, name, email FROM vendors WHERE category = %s", (category,))
        vendors = cursor.fetchall()
        return vendors
    except mysql.connector.Error as err:
        print(f"Error: {err}")
        return []

    
    
@app.route('/user/vendors/<category>')
def vendors_in_category(category):
    vendors = get_vendors_in_category(category)
    vendor_id = vendors[0]
    return render_template('user/vendors_in_category.html', category=category, vendors=vendors, vendor_id=vendor_id)


def get_vendor_items(vendor_id):
    try:
        print("=====cvxcv====ven id",vendor_id)
        cursor.execute("SELECT * FROM products WHERE vendor_id = %s", (vendor_id,))
        items = cursor.fetchall()
        print("=========items id",items)
        for item in items:
            {{ item }}
            print("Item details:")
            print(f"Column 1: {item[0]}") 
            print(f"Column 2: {item[1]}") 
          

        return items
    except mysql.connector.Error as err:
        print(f"Error: ===================={err}")
        return []


@app.route('/user/shop-items/<int:vendor_id>', methods=['GET'])
def shop_items(vendor_id):    
    cursor.execute("SELECT name, category FROM vendors WHERE id = %s", (vendor_id,))
    vendor = cursor.fetchone()
    if vendor:
        vendor_name = vendor[0]
        vendor_category = vendor[1]

        cursor.execute("SELECT id, name, price FROM products WHERE vendor_id = %s", (vendor_id,))
        vendor_items = cursor.fetchall()

        return render_template('user/shop_items.html', vendor_id=vendor_id, vendor_name=vendor_name, vendor_items=vendor_items)
    else:
        flash('Vendor not found', 'danger')
        return redirect(url_for('user_dashboard'))


@app.route('/add-to-cart/<product_id>', methods=['POST', 'GET'])
def add_to_cart(product_id):
    print("========<int:product_id>=======")
    
    print("========<int:product_id>=======",product_id)
    cursor.execute("SELECT name, price FROM products WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if product:
        user_id = session.get('user_id')
        if user_id:
            cursor.execute(
                "INSERT INTO user_cart (user_id, product_id, name, price, quantity) VALUES (%s, %s, %s, %s, 1)",
                (user_id, product_id, product[0], product[1])
            )
            db.commit()

            flash('Item added to cart successfully', 'success')
        else:
            flash('Please log in to add items to your cart', 'danger')
    else:
        flash('Invalid input data', 'danger')

    return redirect(url_for('view_cart'))

@app.route('/view-cart')
def view_cart():

    user_id = session.get('user_id')
    if user_id:
        cursor.execute("SELECT product_id, name, price, SUM(quantity), price * SUM(quantity) FROM user_cart WHERE user_id = %s GROUP BY product_id, name, price", (user_id,))
        cart_items = cursor.fetchall()
        total_price = sum(item[4] for item in cart_items)

        return render_template('user/shopping_cart.html', cart_items=cart_items, total_price=total_price)
    else:
        flash('Please log in to view your cart', 'danger')
        return redirect(url_for('user_login'))

    
    

@app.route('/remove-from-cart/<int:product_id>', methods=['POST'])
def remove_from_cart(product_id):
    user_id = session.get('user_id')

    if not user_id:
        flash('Please log in to manage your shopping cart.', 'danger')
        return redirect(url_for('user_login'))

    cursor.execute("SELECT id FROM user_cart WHERE user_id = %s AND product_id = %s", (user_id, product_id))
    item = cursor.fetchone()

    if item:

        cursor.execute("DELETE FROM user_cart WHERE id = %s", (item[0],))
        db.commit()
        flash('Item removed from the shopping cart.', 'success')
    else:
        flash('Item not found in your shopping cart.', 'danger')

    return redirect(url_for('view_cart'))

@app.route('/user/cart/checkout', methods=['GET', 'POST'])
def checkout():

    
    if request.method == 'POST':
        user_id = session.get('user_id')
        if user_id:
            cursor = db.cursor()
            cursor.execute("SELECT price FROM user_cart WHERE user_id = %s", (user_id,))
            cart_items = cursor.fetchall()
            total_price = sum(item[0] for item in cart_items)
            print("========total_price========",total_price)
            name = request.form['name']
            email = request.form['email']
            address = request.form['address']
            city = request.form['city']
            phone_number = request.form.get('phone_number')

            payment_method = request.form['payment_method']
            state = request.form['state']
            pin_code = request.form['pin_code']

            cursor.execute(
                "INSERT INTO orders (user_id, name, email, address, city, phone_number, payment_method, state, pin_code, total_price) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                (user_id, name, email, address, city, phone_number, payment_method, state, pin_code, total_price)
            )
            db.commit()
            cursor.execute("DELETE FROM user_cart WHERE user_id = %s", (user_id,))
            db.commit()

            return render_template('user/order_confirmation.html', total_price=total_price, name=name, email=email, address=address, city=city, phone_number=phone_number, payment_method=payment_method, state=state, pin_code=pin_code)

        flash('Please log in to complete the order.', 'danger')
        return redirect(url_for('user_login'))

    return render_template('user/checkout.html')



if __name__ == '__main__':
    app.run(port= 6060,debug=True)