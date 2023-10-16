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

# ==============admin===============

@app.route('/api/maintenance-menu', methods=['GET'])
def maintenance_menu_api():
    if 'admin_id' in session:
        admin_id = session['admin_id']
        
        return jsonify({"message": "Admin access to maintenance menu granted."})
    else:
        return jsonify({"error": "Access denied. Please log in as an admin."}), 401
    
    
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
            # Successful login
            session['admin_id'] = admin[0]  # Set the 'admin_id' session variable
            flash('Login successful', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Login failed. Please check your credentials.', 'danger')

    return render_template('admin/login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' in session:
        # You can add any existing logic for the admin dashboard here
        return render_template('admin/dashboard.html')
    else:
        flash('Access denied. Please log in as an admin.', 'danger')
        return redirect(url_for('admin_login'))

@app.route('/admin/maintenance-menu')
def maintenance_menu():
    if 'admin_id' in session:
        # Add your maintenance-related functionality here
        return render_template('admin/maintenance_menu.html')
    else:
        flash('Access denied. Please log in as an admin.', 'danger')
        return redirect(url_for('admin_login'))

# ========================
def get_user_data(user_id):
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return cursor.fetchone()

def get_all_users():
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

def get_all_users():
    cursor.execute("SELECT * FROM users")
    return cursor.fetchall()

@app.route('/admin/maintain-user')
def maintain_user():
    if 'admin_id' not in session:
        flash('Please log in as an admin to access this page.', 'danger')
        return redirect(url_for('admin_login'))

    users = get_all_users()  # Use the modified function to retrieve all users.
    print("========users",users)
    return render_template('admin/maintain_user.html', users=users)



    
def insert_user(name, email, password):
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
            (name, email, hashed_password)
        )
        db.commit()

        return True  # Return True if the user is inserted successfully
    except mysql.connector.Error as err:
        db.rollback()
        print(f"Error: {err}")
        return False  # Return False if there's an error during insertion

# --------------add user

# Updated Logic for Adding a User (Flask Application)

@app.route('/admin/add-user', methods=['GET', 'POST'])
def add_user():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # Hash the user's password
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor.execute(
                "INSERT INTO users (name, email, password) VALUES (%s, %s, %s)",
                (name, email, hashed_password)
            )
            db.commit()

            return redirect(url_for('maintain_user', success=True))  # Redirect with success=True

        except mysql.connector.Error as err:
            db.rollback()
            flash(f"Error: {err}", 'danger')

    return render_template('admin/add_user.html')

# ============add vendor
def get_all_vendors():
    cursor.execute("SELECT * FROM vendors")
    return cursor.fetchall()


@app.route('/admin/maintain-vendor')
def maintain_vendors():
    if 'admin_id' not in session:
        flash('Please log in as an admin to access this page.', 'danger')
        return redirect(url_for('admin_login'))

    # Retrieve a list of vendors from the database
    vendors = get_all_vendors()  # Implement this function to retrieve all vendors

    return render_template('admin/maintain_vendor.html', vendors=vendors)


def insert_vendor(name, email, password, category):
    try:
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        cursor = db.cursor()
        cursor.execute(
            "INSERT INTO vendors (name, email, password, category) VALUES (%s, %s, %s, %s)",
            (name, email, hashed_password, category)
        )
        db.commit()

        return True  # Return True if the vendor is inserted successfully
    except mysql.connector.Error as err:
        db.rollback()
        print(f"Error: {err}")
        return False  # Return False if there's an error during insertion


@app.route('/admin/add-vendor', methods=['GET', 'POST'])
def add_vendor():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        category = request.form['category']

        # Hash the password using bcrypt
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            cursor.execute(
                "INSERT INTO vendors (name, email, password, category) VALUES (%s, %s, %s, %s)",
                (name, email, hashed_password, category)
            )
            db.commit()

            flash('Vendor added successfully', 'success')  # Set success message
            return redirect(url_for('maintain-vendor'))
        except mysql.connector.Error as err:
            db.rollback()
            flash(f"Error: {err}", 'danger')

    return render_template('admin/add_vendor.html')

@app.route('/admin/update-vendor/<int:vendor_id>', methods=['GET', 'POST'])
def update_vendor(vendor_id):
    if 'admin_id' not in session:
        flash('Please log in as an admin to access this page.', 'danger')
        return redirect(url_for('admin_login'))

    cursor.execute("SELECT * FROM vendors WHERE id = %s", (vendor_id,))
    vendor = cursor.fetchone()

    if request.method == 'POST':
        updated_name = request.form['vendor_name']
        updated_email = request.form['vendor_email']
        updated_category = request.form['category']  # Change 'vendor_category' to 'category' here

        try:
            cursor.execute(
                "UPDATE vendors SET name = %s, email = %s, category = %s WHERE id = %s",
                (updated_name, updated_email, updated_category, vendor_id)
            )
            db.commit()

            flash('Vendor updated successfully', 'success')
            return redirect(url_for('maintain_vendors'))
        except mysql.connector.Error as err:
            db.rollback()
            flash(f"Error: {err}", 'danger')

    return render_template('admin/update_vendor.html', vendor=vendor, vendor_id=vendor_id)



# ============update user
@app.route('/admin/update-user/<int:user_id>', methods=['GET', 'POST'])
def update_user(user_id):
    if request.method == 'POST':
        updated_name = request.form['updated_name']
        updated_email = request.form['updated_email']

        if update_user_details(user_id, updated_name, updated_email):
            flash('User updated successfully', 'success')
            return redirect(url_for('maintain_user'))

        else:
            flash('Failed to update user. Please try again.', 'danger')

    user = get_user_data(user_id)
    print("====user",user)
    return render_template('admin/update_user.html', user=user)




# ============update


def update_user_details(user_id, name, email):
    try:
        cursor = db.cursor()
        cursor.execute(
            "UPDATE users SET name = %s, email = %s WHERE id = %s",
            (name, email, user_id)
        )
        db.commit()
        return True  # Return True if the user details are updated successfully
    except mysql.connector.Error as err:
        db.rollback()
        print(f"Error: {err}")
        return False  # Return False if there's an error during the update

    

@app.route('/admin/logout', methods=['GET'])
def admin_logout():
    session.pop('admin_id', None)  # Remove the admin's session data
    flash('Admin logged out successfully', 'success')
    return redirect(url_for('landing_page'))  # Redirect to the landing page or any other desired page

# =======================

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

# ==============admin===============




# ==============VEndor===============

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
    print("=======vendor_name,",vendor_name)
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

@app.route('/vendor/logout', methods=['POST','GET'])
def vendor_logout():
    session.pop('vendor_id', None)
    flash('Vendor logged out successfully', 'success')
    return redirect(url_for('landing_page'))


# ==============User===============

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

@app.route('/user/dashboard')
def user_dashboard():
    user_name = session.get('user_name')
    print("========user_name",user_name)
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
    if not vendors:
        flash('No vendors found in this category', 'danger')
        return redirect(url_for('user_dashboard'))
    
    vendor_id = vendors[0]  
    return render_template('user/vendors_in_category.html', category=category, vendors=vendors, vendor_id=vendor_id)



def get_vendor_items(vendor_id):
    try:
        cursor.execute("SELECT * FROM vendor_items WHERE vendor_id = %s", (vendor_id,))
        items = cursor.fetchall()
     
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

        cursor.execute("SELECT id, name, price FROM vendor_items WHERE vendor_id = %s", (vendor_id,))
        vendor_items = cursor.fetchall()
        print("===========vendor_items",vendor_items)
        return render_template('user/shop_items.html', vendor_id=vendor_id, vendor_name=vendor_name, vendor_items=vendor_items)
    else:
        flash('Vendor not found', 'danger')
        return redirect(url_for('user_dashboard'))


@app.route('/add-to-cart/<int:product_id>', methods=['POST', 'GET'])
def add_to_cart(product_id):
    cursor.execute("SELECT id, name, price FROM vendor_items WHERE id = %s", (product_id,))
    product = cursor.fetchone()

    if product:
        product_price = product[2]
        user_id = session.get('user_id')

        if user_id:
            cursor.execute(
                "INSERT INTO user_cart (user_id, product_id, name, price, quantity) VALUES (%s, %s, %s, %s, 1)",
                (user_id, product_id, product[1], product_price)
            )
            db.commit()

        return redirect(url_for('view_cart'))
    else:
        flash('Product not found', 'error')
        return redirect(url_for('view_cart'))

@app.route('/user/cart', methods=['GET'])
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





@app.route('/user/cart/checkout', methods=['GET', 'POST'])
def checkout():
    if request.method == 'POST':
        user_id = session.get('user_id')
        if user_id:
            cursor = db.cursor()
            cursor.execute("SELECT price FROM user_cart WHERE user_id = %s", (user_id,))
            cart_items = cursor.fetchall()
            total_price = sum(item[0] for item in cart_items)

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


@app.route('/remove-from-cart/<int:product_id>', methods=['POST','GET'])
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

@app.route('/user/cart/delete-all', methods=['POST'])
def delete_all_items():
    user_id = session.get('user_id')

    if not user_id:
        flash('Please log in to manage your shopping cart.', 'danger')
        return redirect(url_for('user_login'))

    cursor.execute("DELETE FROM user_cart WHERE user_id = %s", (user_id,))
    db.commit()
    flash('All items removed from the shopping cart.', 'success')

    return redirect(url_for('view_cart'))

@app.route('/user/order-status', methods=['GET'])
def order_status():
    print("=============nnn")
    if 'user_id' not in session:
        flash('Please log in to view order status.', 'danger')
        return redirect(url_for('user_login')) 
    user_id = session['user_id']
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT name, email, address FROM orders WHERE user_id = %s", (user_id,))
    order_info = cursor.fetchone()

    if order_info:
        order_info['status'] = 'Arriving'  
        return render_template('user/order_status.html', order_info=order_info)
    else:
        flash('No order information found.', 'warning')
        return render_template('user/order_status.html', order_info=None)



@app.route('/user/logout', methods=['POST','GET'])
def user_logout():
    session.pop('user_id', None)
    flash('User logged out successfully', 'success')
    return redirect(url_for('landing_page'))

@app.route('/vendor/transactions', methods=['GET'])
def vendor_transactions():
    vendor_id = session.get('vendor_id')
    
    if vendor_id is None:
        flash('Please log in as a vendor to view transactions.', 'danger')
        return redirect(url_for('vendor_login'))
    cursor.execute("SELECT id, user_id, status FROM orders WHERE vendor_id = %s", (vendor_id,))
    orders = cursor.fetchall()
    
    return render_template('vendor/transactions.html', orders=orders)


@app.route('/vendor/update-status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    vendor_id = session.get('vendor_id')
    
    if vendor_id is None:
        flash('Please log in as a vendor to update order status.', 'danger')
        return redirect(url_for('vendor_login'))
    
    new_status = request.form['status']

    cursor.execute("UPDATE orders SET status = %s WHERE id = %s AND vendor_id = %s", (new_status, order_id, vendor_id))
    db.commit()

    flash('Order status updated successfully', 'success')
    return redirect(url_for('vendor_transactions'))

if __name__ == '__main__':
    app.run(port= 6060,debug=True)