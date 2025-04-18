# --- START OF FILE app.py ---

from flask import Flask, render_template, jsonify, request, send_file, session, redirect, url_for, flash
import os
import io
import datetime
import re
from functools import wraps
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from supabase import create_client, Client
from supabase.lib.client_options import ClientOptions
from dotenv import load_dotenv
from dateutil.relativedelta import relativedelta # For time difference formatting
# Removed duplicate import: from flask import request, get_flashed_messages (already imported via Flask)

# Load environment variables
load_dotenv('.env')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Initialize Supabase client with options
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')

# --- Supabase Client Initialization ---
supabase = None # Initialize as None
if not supabase_url or not supabase_key:
    print("Error: SUPABASE_URL or SUPABASE_KEY not found in environment variables.")
else:
    try:
        supabase: Client = create_client(
            supabase_url,
            supabase_key,
            options=ClientOptions(
                postgrest_client_timeout=30,
                schema="public"
            )
        )
        print("Supabase client initialized successfully.")
    except Exception as e:
        print(f"Error initializing Supabase client: {e}")
        supabase = None # Ensure it's None if initialization fails

# Helper function to check Supabase connection
def check_supabase():
    if supabase is None:
        # Avoid flashing message here if it's called frequently before request context is ready
        # Instead, just return False and handle flash in routes if needed
        # flash("Application error: Database connection failed. Please contact support.", "danger")
        print("ERROR check_supabase: Supabase client is None.")
        return False
    return True

# --- CORRECTED CONTEXT PROCESSOR ---
@app.context_processor
def inject_globals():
    user_info = session.get('user', None) # Get user info dict from session

    # --- Fetch current role AND names from DB if user is logged in ---
    if user_info and 'id' in user_info:
        if check_supabase():
            auth_user_id = user_info.get('id')
            try:
                # Query public.users for role, first_name, last_name
                response = supabase.table('users') \
                    .select('role, first_name, last_name') \
                    .eq('auth_user_id', auth_user_id) \
                    .maybe_single() \
                    .execute()

                if response.data:
                    # Update user_info dict with values from the database
                    user_info['role'] = response.data.get('role', 'user')
                    user_info['first_name'] = response.data.get('first_name') # Will be None if null in DB
                    user_info['last_name'] = response.data.get('last_name')  # Will be None if null in DB
                else:
                    # Handle case where user exists in Auth but not yet in public.users
                    print(f"WARNING: No profile found in public.users for auth_id {auth_user_id}. Using session defaults.")
                    # Use the role/names from session (set during login) or defaults
                    user_info['role'] = user_info.get('role', 'user')
                    user_info['first_name'] = user_info.get('first_name') # Get potential initial value
                    user_info['last_name'] = user_info.get('last_name')  # Get potential initial value


            except Exception as e:
                print(f"ERROR: Could not fetch role/name from DB for auth_id {auth_user_id}: {e}")
                # Fallback to existing session values or defaults on error
                user_info['role'] = user_info.get('role', 'user')
                user_info['first_name'] = user_info.get('first_name')
                user_info['last_name'] = user_info.get('last_name')
        else:
             # If DB connection fails, keep the values from the session
             print("WARNING: DB connection failed in context_processor, using session values.")
             user_info['role'] = user_info.get('role', 'user')
             user_info['first_name'] = user_info.get('first_name')
             user_info['last_name'] = user_info.get('last_name')


    # --- Define format_ugx helper ---
    def format_ugx(value):
        try: amount = float(value); return f"UGX {amount:,.0f}"
        except (ValueError, TypeError): return "UGX 0"

    # --- Return the dictionary for the template context ---
    return dict(user=user_info, format_ugx=format_ugx, now=datetime.datetime.utcnow)
# --- END OF CORRECTED CONTEXT PROCESSOR ---

# --- MODIFIED LOGIN ROUTE (Only to store initial names) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if not check_supabase():
         flash("Application error: Database connection failed.", "danger")
         return render_template('login.html', error='System configuration error.')
    if 'access_token' in session and 'user' in session: return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        if not email or not password:
            flash('Email and password are required.', 'warning')
            return render_template('login.html')
        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            user = auth_response.user
            session['access_token'] = auth_response.session.access_token
            session['refresh_token'] = auth_response.session.refresh_token
            # Store initial values from metadata (context processor will update if possible)
            session['user'] = {
                'id': str(user.id),
                'email': user.email,
                'role': user.user_metadata.get('role', 'user') if user.user_metadata else 'user',
                'first_name': user.user_metadata.get('first_name') if user.user_metadata else None,
                'last_name': user.user_metadata.get('last_name') if user.user_metadata else None,
            }
            print(f"Login successful for {email}. Initial session data: {session['user']}")
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            error_message = str(e)
            if "Invalid login credentials" in error_message: flash('Invalid email or password.', 'danger')
            else: flash('An error occurred during login.', 'danger'); print(f"Login error for {email}: {error_message}")
            return render_template('login.html')
    return render_template('login.html')


# Authentication decorator (No changes needed)
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session or 'user' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
@login_required
def index():
    return redirect(url_for('dashboard'))

# Helper function to format time differences nicely (No changes needed)
def time_ago(dt_string):
    if not dt_string: return "N/A"
    try:
        then = datetime.datetime.fromisoformat(dt_string.replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = relativedelta(now, then)
        if delta.years > 0: return f"{delta.years} year{'s' if delta.years > 1 else ''} ago"
        if delta.months > 0: return f"{delta.months} month{'s' if delta.months > 1 else ''} ago"
        if delta.days > 0: return f"{delta.days} day{'s' if delta.days > 1 else ''} ago"
        if delta.hours > 0: return f"{delta.hours} hour{'s' if delta.hours > 1 else ''} ago"
        if delta.minutes > 0: return f"{delta.minutes} minute{'s' if delta.minutes > 1 else ''} ago"
        return "Just now"
    except Exception as e:
        print(f"Error formatting time_ago for '{dt_string}': {e}")
        return "Invalid date"

# --- DASHBOARD ROUTE (No changes needed here for the fix) ---
@app.route('/dashboard')
@login_required
def dashboard():
    # Check connection at the start of the route
    if not check_supabase():
        flash("Application error: Database connection failed. Please contact support.", "danger")
        # Render fallback dashboard even if context processor also failed
        return render_template('dashboard.html', error='Database connection failed.', total_sales=0, total_transactions=0, top_products=[], low_stock_count=0, out_of_stock_count=0, recent_customers=[], recent_transactions=[])

    try:
        today_start = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + datetime.timedelta(days=1)

        # Fetch Dashboard Data (keep existing logic)
        sales_response = supabase.table('transactions').select('total_amount').gte('date', today_start.isoformat()).lt('date', today_end.isoformat()).execute()
        total_sales = sum(txn['total_amount'] for txn in sales_response.data) if sales_response.data else 0

        txn_count_response = supabase.table('transactions').select('id', count='exact').gte('date', today_start.isoformat()).lt('date', today_end.isoformat()).execute()
        total_transactions = txn_count_response.count if hasattr(txn_count_response, 'count') else 0

        top_products_response = supabase.rpc('get_top_products', {'query_date': today_start.date().isoformat()}).execute()
        top_products = [{'name': p['name'], 'units': p['units']} for p in top_products_response.data] if top_products_response.data else []

        low_stock_response = supabase.table('products').select('id', count='exact').gt('stock_quantity', 0).lte('stock_quantity', 5).execute()
        low_stock_count = low_stock_response.count if hasattr(low_stock_response, 'count') else 0

        out_of_stock_response = supabase.table('products').select('id', count='exact').eq('stock_quantity', 0).execute()
        out_of_stock_count = out_of_stock_response.count if hasattr(out_of_stock_response, 'count') else 0

        recent_customers_response = supabase.rpc('get_recent_customers').execute()
        recent_customers = []
        if recent_customers_response.data:
            for customer in recent_customers_response.data:
                recent_customers.append({'name': customer.get('name', 'Unknown'), 'time_ago': time_ago(customer.get('latest_transaction'))})

        recent_transactions_response = supabase.table('transactions').select('id, transaction_code, date, total_amount, customers(name)').order('date', desc=True).limit(5).execute()
        recent_transactions = []
        if recent_transactions_response.data:
            for txn in recent_transactions_response.data:
                recent_transactions.append({
                    'id': txn['transaction_code'],
                    'date': datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%Y %I:%M %p'),
                    'customer_name': txn['customers']['name'] if txn['customers'] else 'N/A',
                    'total': txn['total_amount']
                })

        return render_template(
            'dashboard.html',
            total_sales=total_sales,
            total_transactions=total_transactions,
            top_products=top_products,
            low_stock_count=low_stock_count,
            out_of_stock_count=out_of_stock_count,
            recent_customers=recent_customers,
            recent_transactions=recent_transactions
        )

    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        flash(f"Error loading dashboard data: {str(e)}", "danger")
        return render_template(
            'dashboard.html', total_sales=0, total_transactions=0, top_products=[],
            low_stock_count=0, out_of_stock_count=0, recent_customers=[], recent_transactions=[],
            error="Could not load all dashboard data."
        )


# --- MODIFIED REGISTER ROUTE ---
@app.route('/register', methods=['GET', 'POST'])
def register():
    if not check_supabase():
        flash("Application error: Database connection failed.", "danger")
        # Assuming registration form is part of login.html
        return render_template('login.html', reg_error='System configuration error.')

    if 'access_token' in session and 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name', '').strip() # Get and strip whitespace
        last_name = request.form.get('last_name', '').strip()   # Get and strip whitespace

        # --- Validation ---
        error = None
        if not email or not password or not confirm_password or not first_name or not last_name:
            error = "All fields (First Name, Last Name, Email, Password, Confirm Password) are required."
        elif not re.match(r"^\S+@\S+\.\S+$", email): error = "Invalid email format."
        elif len(password) < 8: error = "Password must be at least 8 characters."
        elif password != confirm_password: error = "Passwords do not match."
        # Basic name validation (optional)
        elif len(first_name) < 1: error = "First name cannot be empty."
        elif len(last_name) < 1: error = "Last name cannot be empty."


        if error:
            flash(error, 'danger')
            # Return form values to refill the form, except passwords
            # Pass back names and email to the template context for the form
            return render_template('login.html', reg_email=email, reg_first_name=first_name, reg_last_name=last_name)

        try:
            user_role_to_set = "user" # Default role for new signups
            # --- Register user with Supabase Auth (include names in metadata) ---
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "role": user_role_to_set,
                        "first_name": first_name, # Add to metadata
                        "last_name": last_name    # Add to metadata
                    }
                }
            })

            if auth_response.user:
                 auth_user = auth_response.user
                 print(f"Auth Registration successful for {email}. Auth User ID: {auth_user.id}")

                 # --- Add user to public.users table (include names) ---
                 try:
                     username = email.split('@')[0] # Or derive differently if needed
                     user_profile_data = {
                         'auth_user_id': str(auth_user.id),
                         'email': email,
                         'username': username,
                         'role': user_role_to_set,
                         'first_name': first_name, # Add to profile data
                         'last_name': last_name    # Add to profile data
                     }
                     print(f"Attempting to insert into public.users: {user_profile_data}")
                     insert_response = supabase.table('users').insert(user_profile_data).execute()

                     if insert_response.data and len(insert_response.data) > 0:
                          print(f"Successfully inserted profile into public.users for {email}.")
                          flash("Registration successful! Please check your email to confirm your account.", 'success')
                     else:
                         error_details = getattr(insert_response, 'error', None) or getattr(insert_response, 'message', 'Unknown error')
                         print(f"WARNING: Auth user created, but FAILED to insert profile data into public.users for {email}. Response: {error_details}")
                         # Potentially attempt to delete the auth user here for consistency? Or rely on manual cleanup.
                         flash("Registration successful, but profile creation failed. Please contact support.", 'warning')

                 except Exception as profile_error:
                     print(f"CRITICAL: Auth user created, but EXCEPTION occurred inserting into public.users for {email}: {profile_error}")
                     # Potentially attempt to delete the auth user here.
                     flash("Registration successful, but profile setup encountered an issue. Please contact support.", 'warning')

                 return redirect(url_for('login')) # Redirect to login regardless of profile insert status for now

            else:
                 print(f"Registration response for {email} did not contain user object. Response: {auth_response}")
                 flash("Registration submitted, but encountered an issue. Please check email or try again.", 'warning')
                 return redirect(url_for('login'))

        except Exception as e:
            error_message = str(e)
            print(f"Registration error: {error_message}")
            # Handle specific errors
            if 'User already registered' in error_message or ('status_code' in dir(e) and getattr(e, 'status_code', 0) == 400) or 'users_email_key' in error_message:
                 flash("This email address is already registered.", 'warning')
            elif 'users_username_key' in error_message :
                 flash("This username is already taken.", 'warning')
            elif 'duplicate key value violates unique constraint' in error_message :
                 flash("An account with this email or username might already exist.", 'warning')
            else:
                flash(f"Registration failed: {error_message}", 'danger')
            # Pass back names and email
            return render_template('login.html', reg_email=email, reg_first_name=first_name, reg_last_name=last_name)

    # GET request - show the login/register page
    # Pass empty strings initially for the reg form fields
    return render_template('login.html', reg_email='', reg_first_name='', reg_last_name='')

# --- LOGOUT ROUTE (No changes needed here for the fix) ---
@app.route('/logout')
def logout():
    print("\n--- Logout Route ---")
    access_token = session.get('access_token')
    user_email = session.get('user',{}).get('email','UNKNOWN_USER')

    if access_token and check_supabase(): # Check supabase connection before trying to sign out
        try:
            supabase.auth.sign_out()
            print(f"Supabase sign out successful for {user_email}.")
        except Exception as e:
            print(f"Error during Supabase sign out for {user_email}: {str(e)}")

    session.clear()
    flash("You have been successfully logged out.", 'success')
    print(f"Flashed logout message. Session cleared.")
    return redirect(url_for('login'))


# Helper function to refresh the session token (use cautiously)
def refresh_session():
     # Removed for brevity - add back if needed, ensure error handling is robust
     pass


# =========================================
# Main Application Page Routes (Products, Transactions, Customers, Reports unchanged)
# =========================================
@app.route('/products')
@login_required
def products():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return render_template('products.html', products=[])
    try:
        response = supabase.table('products').select('*').order('name').execute()
        return render_template('products.html', products=response.data or [])
    except Exception as e:
        print(f"Error fetching products: {e}")
        flash("Could not load product data.", "danger")
        return render_template('products.html', products=[])

@app.route('/transactions')
@login_required
def transactions():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return render_template('transactions.html', transactions=[])
    try:
        response = supabase.table('transactions').select('*, customers(name)').order('date', desc=True).execute()
        transactions_data = []
        if response.data:
            for txn in response.data:
                 transactions_data.append({
                    'id': txn['transaction_code'],
                    'date': datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%Y %I:%M %p'),
                    'customer_name': txn['customers']['name'] if txn['customers'] else 'N/A',
                    'total': txn['total_amount']
                })
        return render_template('transactions.html', transactions=transactions_data)
    except Exception as e:
        print(f"Error fetching transactions: {e}")
        flash("Could not load transaction data.", "danger")
        return render_template('transactions.html', transactions=[])


@app.route('/customers')
@login_required
def customers():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return render_template('customers.html', customers=[])
    try:
        response = supabase.table('customers').select('*').order('name').execute()
        return render_template('customers.html', customers=response.data or [])
    except Exception as e:
        print(f"Error fetching customers: {e}")
        flash("Could not load customer data.", "danger")
        return render_template('customers.html', customers=[])


@app.route('/reports')
@login_required
def reports():
    return render_template('reports.html')


# --- MODIFIED USERS ROUTE ---
@app.route('/users')
@login_required
def users():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return redirect(url_for('dashboard'))

    # Authorization Check using DB Role (no change needed here)
    current_user_session = session.get('user')
    if not current_user_session or 'id' not in current_user_session:
        flash("Authentication error.", "danger")
        return redirect(url_for('login'))
    auth_user_id = current_user_session.get('id')
    user_is_admin = False
    try:
        response = supabase.table('users').select('role').eq('auth_user_id', auth_user_id).maybe_single().execute()
        if response.data and response.data.get('role') == 'admin': user_is_admin = True
    except Exception as e: print(f"ERROR: Could not perform role check query for auth_id {auth_user_id}: {e}"); user_is_admin = False
    if not user_is_admin:
        flash("You do not have permission to view this page.", "warning")
        return redirect(url_for('dashboard'))

    # --- Proceed with fetching user data (add first_name, last_name) ---
    try:
        # Select the new name columns
        response = supabase.table('users') \
            .select('id, username, email, role, auth_user_id, first_name, last_name') \
            .order('username', desc=False) \
            .execute()
        users_data = response.data if response.data else []
        return render_template('users.html', users=users_data)
    except Exception as e:
        print(f"Error fetching users list from public.users: {e}")
        flash("Could not load user data due to a server error.", "danger")
        return render_template('users.html', users=[])


# =========================================
# API Routes (Report Generation - Unchanged)
# =========================================
@app.route('/api/reports/<period>', methods=['GET'])
@login_required
def generate_report_api(period):
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    today = datetime.datetime.now().date()
    end_date = today

    if period == 'daily': start_date = today
    elif period == 'weekly': start_date = today - datetime.timedelta(days=today.weekday())
    elif period == 'monthly': start_date = today.replace(day=1)
    else: return jsonify({'error': 'Invalid report period specified'}), 400

    title_map = {
        'daily': f"Daily Report - {today.strftime('%d %b %Y')}",
        'weekly': f"Weekly Report ({start_date.strftime('%d %b')} - {end_date.strftime('%d %b %Y')})",
        'monthly': f"Monthly Report - {start_date.strftime('%B %Y')}"
    }
    title = title_map.get(period)

    start_datetime = datetime.datetime.combine(start_date, datetime.time.min)
    end_datetime = datetime.datetime.combine(end_date, datetime.time.max)

    try:
        transactions_response = supabase.table('transactions') \
            .select('date, transaction_code, total_amount, customers(name)') \
            .gte('date', start_datetime.isoformat()) \
            .lte('date', end_datetime.isoformat()) \
            .order('date') \
            .execute()
        transactions = transactions_response.data if transactions_response.data else []

        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter
        p.setFont('Helvetica-Bold', 16)
        p.drawString(50, height - 50, "Bash Merchandise Management")
        p.setFont('Helvetica', 14)
        p.drawString(50, height - 70, title)
        p.setFont('Helvetica', 10)
        p.line(50, height - 80, width - 50, height - 80)

        y_position = height - 100
        x_positions = [50, 150, 300, 450] # Adjusted X positions slightly
        headers = ["Date", "Transaction ID", "Customer", "Amount (UGX)"]
        p.setFont('Helvetica-Bold', 10)
        for i, header in enumerate(headers): p.drawString(x_positions[i], y_position, header)

        y_position -= 15
        p.setFont('Helvetica', 9)
        total_report_amount = 0

        for txn in transactions:
            if y_position < 60:
                p.showPage()
                p.setFont('Helvetica-Bold', 10)
                y_position = height - 100
                for i, header in enumerate(headers): p.drawString(x_positions[i], y_position, header)
                y_position -= 15
                p.setFont('Helvetica', 9)

            date_str = datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%y %H:%M')
            txn_id = txn['transaction_code']
            customer = txn['customers']['name'] if txn['customers'] else 'N/A'
            amount = txn['total_amount']
            total_report_amount += amount

            p.drawString(x_positions[0], y_position, date_str)
            p.drawString(x_positions[1], y_position, txn_id)
            p.drawString(x_positions[2], y_position, customer)
            # Ensure format_ugx is available or use direct f-string formatting
            try: amount_str = f"{float(amount):,.0f}"
            except: amount_str = "Invalid"
            p.drawRightString(x_positions[3] + 100, y_position, amount_str) # Right align amount

            y_position -= 15

        p.line(50, y_position + 5, width - 50, y_position + 5)
        y_position -= 10
        p.setFont('Helvetica-Bold', 10)
        summary_x_start = x_positions[2] # Align summary labels
        p.drawString(summary_x_start, y_position, "Total Transactions:")
        p.drawRightString(x_positions[3] + 100, y_position, str(len(transactions)))
        y_position -= 15
        p.drawString(summary_x_start, y_position, "Total Amount (UGX):")
        try: total_amount_str = f"{float(total_report_amount):,.0f}"
        except: total_amount_str = "Invalid"
        p.drawRightString(x_positions[3] + 100, y_position, total_amount_str)

        p.save()
        buffer.seek(0)
        download_filename = f"BashMerch_{period}_report_{today.strftime('%Y%m%d')}.pdf"
        return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=download_filename)

    except Exception as e:
        print(f"Error generating {period} report: {e}")
        # Consider logging the full traceback here for debugging
        import traceback
        traceback.print_exc()
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500

# --- REMOVED DUPLICATE format_ugx definition and incorrect return statement ---

# =========================================
# Run the Application
# =========================================
if __name__ == '__main__':
    if supabase is None:
        print("\nCRITICAL ERROR: Supabase client failed to initialize. Cannot start Flask app.")
        print("Please check your .env file for SUPABASE_URL and SUPABASE_KEY and network connection.\n")
    else:
        port = int(os.environ.get('PORT', 5000))
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        print(f"Starting Flask app on http://0.0.0.0:{port} with debug={debug_mode}")
        app.run(debug=debug_mode, host='0.0.0.0', port=port)

# --- END OF FILE app.py ---