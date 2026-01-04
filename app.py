import os
import requests
import sqlite3
import uuid
from datetime import datetime
from flask import Flask, flash, Blueprint, redirect, url_for, render_template, request, session, jsonify, g
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from checkout import checkout_bp

# Configure application
app = Flask(__name__)


DATABASE = "voltkits.db"

def get_db():
    db = getattr(g, "_database", None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row  # return rows as dictionaries
    return db


@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, "_database", None)
    if db is not None:
        db.close()


# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)



@app.before_request
def load_logged_in_user():
    user_id = session.get("user_id")
    if user_id:
        g.user = get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    else:
        g.user = None


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def ensure_guest_id():
    if 'guest_id' not in session:
        session['guest_id'] = str(uuid.uuid4())
    return session['guest_id']


def generate_order_number():
    year = datetime.now().year
    db = get_db()
    count = db.execute(
    "SELECT COUNT(*) FROM orders WHERE strftime('%Y', created_at) = ?",
    (str(year),)
    ).fetchone()[0]
    return f"VOLT-{year}-{str(count + 1).zfill(6)}"




@app.route("/")
def index():
    trending = get_db().execute("""
        SELECT
            p.id,
            p.name,
            p.price,
            (
                SELECT image_url
                FROM product_images
                WHERE product_id = p.id
                ORDER BY id ASC
                LIMIT 1
            ) AS first_image,
            (
                SELECT c.name
                FROM categories c
                JOIN subcategories s ON s.category_id = c.id
                WHERE s.id = p.subcategory_id
            ) AS category_name
        FROM products p
        WHERE p.is_featured = 1
        ORDER BY p.id DESC

    """).fetchall()

    for product in trending:
        print("IMAGE:", product["first_image"])





    return render_template("index.html", trending=trending)


@app.route("/about", methods=["GET", "POST"])
def about():
    return render_template("about.html")


@app.route("/shippingpolicy", methods=["GET"])
def shippingpolicy():
    return render_template("shippingpolicy.html")



@app.route("/shop")
def shop():
    db = get_db()

    # -----------------------------
    # 1. Read query parameters
    # -----------------------------
    main_slug = request.args.get("main")
    selected_subcategory = request.args.get("subcategory", type=int)
    min_price = request.args.get("min_price", type=float)
    max_price = request.args.get("max_price", type=float)
    partial = request.args.get("partial")

    main_category = None
    grouped_products = []
    available_subcategories = []

    # -----------------------------
    # 2. Resolve main category
    # -----------------------------
    if main_slug:
        main_category = db.execute(
            "SELECT * FROM main_categories WHERE name = ?",
            (main_slug,)
        ).fetchone()

        if not main_category:
            main_category = None

    # -----------------------------
    # 3. If main category exists, build data
    # -----------------------------
    if main_category:
        # Get categories under main category
        categories = db.execute(
            "SELECT * FROM categories WHERE main_category_id = ?",
            (main_category["id"],)
        ).fetchall()

        # Collect all subcategories (for filter dropdown)
        for category in categories:
            subs = db.execute(
                "SELECT * FROM subcategories WHERE category_id = ?",
                (category["id"],)
            ).fetchall()
            available_subcategories.extend(subs)

        # Build grouped products
        for subcat in available_subcategories:

            # Apply subcategory filter
            if selected_subcategory and subcat["id"] != selected_subcategory:
                continue

            # Base product query
            query = "SELECT * FROM products WHERE subcategory_id = ?"
            params = [subcat["id"]]

            # Apply price filters
            if min_price is not None:
                query += " AND price >= ?"
                params.append(min_price)

            if max_price is not None:
                query += " AND price <= ?"
                params.append(max_price)

            products_rows = db.execute(query, params).fetchall()

            if not products_rows:
                continue

            products = []
            for row in products_rows:
                product = dict(row)

                img = db.execute(
                    """
                    SELECT image_url
                    FROM product_images
                    WHERE product_id = ?
                    ORDER BY id ASC
                    LIMIT 1
                    """,
                    (product["id"],)
                ).fetchone()

                product["first_image"] = img["image_url"] if img else None
                products.append(product)

                print("Main category:", main_category)
                for category in categories:
                    print("Category:", category["id"], category["name"])
                    subs = db.execute("SELECT * FROM subcategories WHERE category_id = ?", (category["id"],)).fetchall()
                    print("Subcategories:", [(s["id"], s["name"]) for s in subs])


            grouped_products.append({
                "subcategory": subcat,
                "products": products
            })

    # -----------------------------
    # 4. Choose template (full or partial)
    # -----------------------------
    template = (
        "partials/shop_content.html"
        if partial
        else "shop.html"
    )

    return render_template(
        template,
        main_category=main_category,
        grouped_products=grouped_products,
        available_subcategories=available_subcategories,
        selected_subcategory=selected_subcategory,
        min_price=min_price,
        max_price=max_price
    )



@app.route("/products/subcategory/<int:subcat_id>")
def products_by_subcategory(subcat_id):
    db = get_db()

    # 1) Get subcategory
    subcategory = db.execute(
        "SELECT * FROM subcategories WHERE id = ?", (subcat_id,)
    ).fetchone()
    if subcategory is None:
        return "Subcategory not found", 404

    # 2) Get category
    category = db.execute(
        "SELECT * FROM categories WHERE id = ?", (subcategory["category_id"],)
    ).fetchone()
    if category is None:
        return "Category not found", 404

    # 3) Get main category
    main_category = db.execute(
        "SELECT * FROM main_categories WHERE id = ?", (category["main_category_id"],)
    ).fetchone()
    if main_category is None:
        return "Main category not found", 404

    # 4) Get products and images
    products_rows = db.execute(
        "SELECT * FROM products WHERE subcategory_id = ?", (subcat_id,)
    ).fetchall()

    # --- FIX 2: Convert rows to real dictionaries to allow modification ---
    products = []
    for row in products_rows:
        # Convert the immutable DB row to a mutable Python dictionary
        product = dict(row)

        images = db.execute(
            "SELECT image_url FROM product_images WHERE product_id = ? ORDER BY id ASC",
            (product["id"],)
        ).fetchall()

        # Convert from row objects to plain strings
        product["image_paths"] = [img["image_url"] for img in images]
        products.append(product)

    return render_template(
        "products_by_subcategory.html",
        main_category=main_category,
        category=category,
        subcategory=subcategory,
        products=products
    )




@app.route("/product/<int:product_id>")
def product_details(product_id):
    db = get_db() # Get DB connection early for repeated use

    # 1. Get product info (FIX: Changed .fetchnone() to .fetchone())
    product_row = db.execute(
        "SELECT * FROM products WHERE id = ?", (product_id,)
    ).fetchone()

    if not product_row:
        return "Product not found", 404

    # 2. FIX: Convert the immutable row to a mutable dictionary
    product = dict(product_row)

    # Get product images
    images = db.execute(
        "SELECT image_url FROM product_images WHERE product_id = ? ORDER BY id ASC",
        (product_id,)
    ).fetchall()
    product['image_paths'] = [img['image_url'] for img in images]

    subcategory = db.execute(
        "SELECT * FROM subcategories WHERE id = ?", (product["subcategory_id"],)
    ).fetchone()
    if subcategory is None:
        return "Subcategory not found", 404

    # 2) Get category
    category = db.execute(
        "SELECT * FROM categories WHERE id = ?", (subcategory["category_id"],)
    ).fetchone()
    if category is None:
        return "Category not found", 404


    # Related products: Fetch the data and store it appropriately
    related_products_rows = db.execute(
        "SELECT * FROM products WHERE subcategory_id = ? AND id != ? LIMIT 4",
        (product["subcategory_id"], product_id)
    ).fetchall()

    # Initialize the final list for the template
    related_products = []

    # Process each related product row
    for p_row in related_products_rows:
        # Convert each row to a dictionary for modification (adding 'first_image')
        p = dict(p_row)

        # Get the single image (FIX: Used the pre-assigned 'db' variable)
        imgs = db.execute(
            "SELECT image_url FROM product_images WHERE product_id = ? ORDER BY id ASC LIMIT 1",
            (p["id"],)
        ).fetchall() # Returns a list

        # Access the image only if the list (imgs) is not empty
        p["first_image"] = imgs[0]["image_url"] if imgs else None

        related_products.append(p)

    return render_template("product_details.html",
        product=product,
        related_products=related_products,
        category=category,
        subcategory=subcategory)




@app.route("/cart", methods=["GET", "POST"])
def cart():
    db = get_db()
    if "cart" not in session:
        session["cart"] = []

    if request.method == "POST":
        try:
            product_id = int(request.form.get("product_id"))
            size = request.form.get("size", "").strip()
            quantity_raw = request.form.get("quantity", "").strip()
            quantity = int(quantity_raw) if quantity_raw else 1
        except (ValueError, TypeError):
            return jsonify({"success": False, "message": "Invalid product or quantity"}), 400

        product_row = db.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
        if not product_row:
            return jsonify({"success": False, "message": "Product not found"}), 404
        product = dict(product_row)

        images = db.execute(
            "SELECT image_url FROM product_images WHERE product_id = ? ORDER BY id ASC LIMIT 1",
            (product["id"],)
        ).fetchone()
        image_url = images["image_url"] if images else ""

        cart_item = {
            "product_id": product["id"],
            "name": product["name"],
            "price": product.get("price", 0),
            "size": size,
            "quantity": quantity,
            "image": image_url
        }

        updated = False
        for item in session["cart"]:
            if item["product_id"] == product["id"] and item["size"] == size:
                item["quantity"] += quantity
                updated = True
                break
        if not updated:
            session["cart"].append(cart_item)

        session.modified = True

        # Return JSON instead of redirect
        return jsonify({
            "success": True,
            "message": f'Added {quantity} x {product["name"]} to cart!',
            "cart_count": sum(item["quantity"] for item in session["cart"])
        })

    # GET request: render cart page as usual
    cart_items = session.get("cart", [])
    total = sum(item["price"] * item["quantity"] for item in cart_items)
    return render_template("cart.html", cart_items=cart_items, total=total)


@app.route("/cart/update", methods=["POST"])
def update_cart():
    try:
        product_id = int(request.form.get("product_id"))
        size = request.form.get("size")
        action = request.form.get("action")  # "increment", "decrement", "remove"
    except (ValueError, TypeError):
        return jsonify({"success": False, "message": "Invalid data"})

    cart = session.get("cart", [])

    for item in cart:
        if item.get("product_id") == product_id and item.get("size") == size:
            if action == "increment":
                item["quantity"] += 1
            elif action == "decrement" and item["quantity"] > 1:
                item["quantity"] -= 1
            elif action == "remove":
                cart.remove(item)
            break

    session["cart"] = cart
    session.modified = True

    total = sum(i.get("price", 0) * i.get("quantity", 1) for i in cart)
    cart_count = sum(i.get("quantity", 0) for i in cart)


    return jsonify({
        "success": True,
        "quantity": item.get("quantity", 0) if action != "remove" else 0,
        "total": total,
        "cart_count":cart_count
    })






@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"].lower()
        password = request.form["password"]

        user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if not user:
            return render_template("login.html", error="Email not found")

        if not check_password_hash(user["password_hash"], password):
            return render_template("login.html", error="Incorrect password")

        session["user_id"] = user["id"]

        flash("Logged in", "success")
        return redirect("/")

    return render_template("login.html")



@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    flash("Logged out", "danger")
    return redirect("/")



@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        first_name = request.form["first_name"]
        last_name = request.form["last_name"]
        email = request.form["email"].lower()
        password = request.form["password"]

        if get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone():
            return render_template("signup.html", error="An account with this email already exists")

        password_hash = generate_password_hash(password)
        db = get_db()
        db.execute("""
            INSERT INTO users (first_name, last_name, email, password_hash)
            VALUES (?, ?, ?, ?)
        """, (first_name, last_name, email, password_hash))
        db.commit()

        flash("Account created", "success")
        return redirect("/")

    return render_template("signup.html")


@app.route("/checkout/email-check", methods=["POST"])
def email_check():
    data = request.json or {}
    email = data.get("email")
    if not email:
        return jsonify({"success": False, "error": "Email required"}), 400
    user = get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        return jsonify({"Sorry, this email address does not exist in our database"})
    return jsonify({"success": True, "email_exists": bool(user)})


@app.route("/checkout/auth", methods=["POST"])
def checkout_auth():
    data = request.json
    email = data.get("email")
    action = data.get("action")
    password = data.get("password")

    if action == "login":
        if login_user(email, password):  # your login function
            return jsonify({"success": True})
        else:
            return jsonify({"success": False, "message": "Invalid credentials"})
    elif action == "register":
        create_user(email, password)  # immediately create account (Option B)
        login_user(email, password)
        return jsonify({"success": True})


def calculate_cart_subtotal():
    subtotal = 0
    for item in session.get('cart', []):
        subtotal += item['price'] * item['quantity']
    return subtotal



@checkout_bp.route('/start', methods=['POST'])
def checkout_start():
    ensure_guest_id()
    data = request.get_json(silent=True) or {}
    mode = data.get('mode')  # 'guest' or 'email'
    email = data.get('email')

    db = get_db()

    # validate cart not empty
    if not session.get('cart'):
        return jsonify({'success': False, 'error': 'Cart empty'}), 400

    # create draft order
    order_number = generate_order_number()
    subtotal = calculate_cart_subtotal()
    user_id = g.user['id'] if g.user else None

    db.execute("""
      INSERT INTO orders (order_number, user_id, session_id, subtotal)
      VALUES (?, ?, ?, ?)
    """, (order_number, user_id, session['guest_id'], subtotal))
    db.commit()

    order_id = db.execute("SELECT id FROM orders WHERE order_number = ?", (order_number,)).fetchone()['id']

    # Insert order items (commit once)
    for item in session.get('cart', []):
        quantity = item.get('quantity')

        db.execute(
            """
            INSERT INTO order_items
            (order_id, product_id, product_name, unit_price, quantity)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                order_id,
                item['product_id'],
                item['name'],
                item['price'],
                quantity
            )
        )

        db.commit()

    session['order_id'] = order_id

    # Decide next
    if mode == 'email':
        # check if email exists in users table
        exists = None
        if email:
            exists = db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone()
            # save email to order now
            db.execute("UPDATE orders SET email = ? WHERE id = ?", (email, order_id))
            db.commit()

        if exists:
            next_step = 'auth'
        else:
            next_step = 'auth'
        return jsonify({'success': True, 'order_number': order_number, 'next': next_step, 'email_exists': bool(exists),'email': email})

    else:
        # guest path
        next_step = 'contact'

    return jsonify({'success': True, 'order_number': order_number, 'next': next_step, 'email': email})




@checkout_bp.route('/fulfillment', methods=['POST'])
def checkout_fulfillment():
    order_id = session.get('order_id')
    if not order_id:
        return jsonify({
            'success': False,
            'errors': {
                '_form': 'Order not started'
            }
        }), 400

    data = request.json or {}


    email = data.get('email', '').strip()
    fullname = data.get('full_name', '').strip()
    phone = data.get('phone', '').strip()
    fulfillment = data.get('fulfillment')

    errors = {}

    # Field validations
    if not fullname:
        errors['fullname'] = 'Full name is required.'

    if not email:
        errors['email'] = 'Email is required.'

    if not phone:
        errors['phone'] = 'Phone number is required.'

    if fulfillment not in ('pickup', 'delivery'):
        errors['fulfillment'] = 'Please select Pickup or Delivery.'

    if errors:
        return jsonify({
            'success': False,
            'errors': errors
        }), 400

    db = get_db()
    db.execute(
        """
        UPDATE orders
        SET email = ?, full_name = ?, phone = ?, fulfillment = ?
        WHERE id = ?
        """,
        (email, fullname, phone, fulfillment, order_id)
    )
    db.commit()

    next_step = 'summary' if fulfillment == 'pickup' else 'shipping'

    return jsonify({
        'success': True,
        'next': next_step
    })



@checkout_bp.route('/checkout/shipping', methods=['POST'])
def checkout_shipping():
    order_id = session.get('order_id')
    if not order_id:
        return jsonify({'success': False, 'error': 'Order not started'}), 400
    data = request.json or {}
    if not all([data.get('address'), data.get('city'), data.get('state')]):
        return jsonify({'success': False, 'error': 'Incomplete address'}), 400
    db = get_db()
    db.execute("""
      INSERT INTO shipping_addresses (order_id, address, city, state, landmark)
      VALUES (?, ?, ?, ?, ?)
    """, (order_id, data['address'], data['city'], data['state'], data.get('landmark')))
    db.commit()
    return jsonify({'success': True, 'next': 'summary'})



@checkout_bp.route('/summary')
def checkout_summary():
    order_id = session.get('order_id')
    if not order_id:
        return jsonify({'error': 'Order not started'}), 400
    db = get_db()
    order = db.execute(
    "SELECT * FROM orders WHERE id = ?",
    (order_id,)
    ).fetchone()
    items = db.execute(
    "SELECT * FROM order_items WHERE order_id = ?",
    (order_id,)
    ).fetchall()
    return jsonify({
    'order': dict(order),
    'items': [dict(i) for i in items]
    })



@checkout_bp.route('/confirm', methods=['POST'])
def checkout_confirm():
    order_id = session.get('order_id')
    if not order_id:
        return jsonify({'success': False, 'error': 'Order not started'}), 400

    db = get_db()

    order = db.execute(
        "SELECT * FROM orders WHERE id = ?",
        (order_id,)
    ).fetchone()

    if not order:
        return jsonify({'success': False, 'error': 'Order not found'}), 404

    if order['status'] == 'paid':
        return jsonify({'success': False, 'error': 'Order already paid'}), 400

    tx_ref = order['order_number']

    # Mark as pending payment
    db.execute(
        "UPDATE orders SET status = ?, payment_reference = ? WHERE id = ?",
        ('pending', tx_ref, order_id)
    )
    db.commit()


    flutterwave_payload = {
        "tx_ref": tx_ref,
        "amount": order['subtotal'],
        "currency": "NGN",
        "redirect_url": url_for('checkout.payment_callback', _external=True),
        "customer": {
            "email": order['email'],
            "name": order['full_name']
        },
        "customizations": {
            "title": "Volt Checkout",
            "description": f"Order {order['order_number']}"
        }
    }

    headers = {
        "Authorization": "Bearer FLWSECK_TEST-435cee7213cc3dc52eb3f927a7167f3e-X",
        "Content-Type": "application/json",
        "X-Scenario-Key": "scenario:auth_3ds&issuer:approved"
    }

    response = requests.post(
        "https://api.flutterwave.com/v3/payments",
        json=flutterwave_payload,
        headers=headers
    )

    data = response.json()


    if data.get('status') != 'success':
        return jsonify({'success': False, 'error': 'Payment initialization failed'}), 500

    return jsonify({
        'success': True,
        'redirect_url': data['data']['link']
    })


@checkout_bp.route('/paymentcallback')
def payment_callback():
    status = request.args.get('status')
    tx_ref = request.args.get('tx_ref')
    transaction_id = request.args.get('transaction_id')

    if status != 'successful':
        return redirect('/checkout/failed')

    headers = {
        "Authorization": "Bearer FLWSECK_TEST-435cee7213cc3dc52eb3f927a7167f3e-X"
    }

    verify_res = requests.get(
        f"https://api.flutterwave.com/v3/transactions/{transaction_id}/verify",
        headers=headers
    )

    data = verify_res.json()

    if data.get('status') != 'success':
        return redirect('/checkout/failed')

    payment = data['data']
    amount = payment['amount']
    ref = payment['tx_ref']

    db = get_db()
    order = db.execute(
        "SELECT * FROM orders WHERE payment_reference = ?",
        (ref,)
    ).fetchone()

    if (order and
            payment['status'] == 'successful' and
            payment['amount'] >= order['subtotal'] and
            payment['currency'] == 'NGN'):

            # 4. Success! Update DB
            db.execute("UPDATE orders SET status = 'paid' WHERE id = ?", (order['id'],))
            db.commit()

    session.pop('cart', None)
    session.pop('order_id', None)

    return redirect(f"/checkout/success?order={order['order_number']}")


@checkout_bp.route('/success')
def success_page():
    order_number = request.args.get('order')
    db = get_db()

    order = db.execute(
        "SELECT * FROM orders WHERE order_number = ?",
        (order_number,)
    ).fetchone()

    if not order:
        return redirect('/') # Redirect home if order doesn't exist

    return render_template('success.html', order=order)


@checkout_bp.route('/failed')
def failed_page():
    # We don't necessarily need to fetch the order,
    # but we should ensure the user is informed.
    return render_template('failed.html')



app.register_blueprint(checkout_bp)


@app.context_processor
def inject_cart_count():
    cart = session.get('cart', [])
    cart_count = sum(item['quantity'] for item in cart)
    return dict(cart_count=cart_count)


