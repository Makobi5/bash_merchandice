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
import babel.dates
from dateutil.relativedelta import relativedelta # For time difference formatting

import psycopg2
from psycopg2.extras import RealDictCursor
import os
from werkzeug.utils import secure_filename
import uuid
# Removed duplicate import: from flask import request, get_flashed_messages (already imported via Flask)

# Load environment variables
load_dotenv('.env')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Configure upload settings (add after app initialization)
app.config['UPLOAD_FOLDER'] = 'uploads'  # Local folder for temporary storage
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Initialize Supabase client with options
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')
supabase_service_key = os.getenv('SUPABASE_SERVICE_KEY') # SERVICE ROLE key

# --- Supabase Client Initialization ---
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY') # ANON key
supabase_service_key = os.getenv('SUPABASE_SERVICE_KEY') # SERVICE ROLE key

# Initialize REGULAR client (using ANON key - for reads, non-admin writes)
supabase: Client | None = None
if not supabase_url or not supabase_key:
    print("Error: SUPABASE_URL or SUPABASE_KEY (anon) not found in environment variables.")
else:
    try:
        supabase = create_client(
            supabase_url,
            supabase_key,
            options=ClientOptions(
                postgrest_client_timeout=30,
                schema="public",
                 # Ensure schema is set if needed
            )
        )
        print("Supabase client (anon) initialized successfully.")
    except Exception as e:
        print(f"Error initializing Supabase client (anon): {e}")
        supabase = None # Ensure it's None if initialization fails

# Initialize ADMIN client (using SERVICE ROLE key - for admin operations)
supabase_admin: Client | None = None
if not supabase_url or not supabase_service_key:
    print("WARNING: SUPABASE_SERVICE_KEY not found. Admin operations (like Auth user deletion/creation) will fail.")
else:
    try:
        supabase_admin = create_client(
            supabase_url,
            supabase_service_key,
            options=ClientOptions(
                postgrest_client_timeout=30,
                schema="public" # Ensure schema is set if needed
            )
        )
        print("Supabase ADMIN client (service) initialized successfully.")
    except Exception as e:
        print(f"Error initializing Supabase ADMIN client (service): {e}")
        supabase_admin = None # Ensure it's None if initialization fails

# Helper functions to check Supabase connections
def check_supabase():
    if supabase is None:
        print("ERROR check_supabase: Supabase client (anon) is None.")
        return False
    return True

def check_supabase_admin():
    if supabase_admin is None:
        print("ERROR check_supabase_admin: Supabase ADMIN client (service) is None.")
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
# --- MODIFIED DASHBOARD ROUTE ---
@app.route('/dashboard')
@login_required
def dashboard():
    # Check connection at the start of the route
    if not check_supabase():
        flash("Application error: Database connection failed. Please contact support.", "danger")
        # Render fallback dashboard even if context processor also failed
        # Removed recent_customers from the fallback render_template context
        return render_template('dashboard.html', error='Database connection failed.', total_sales=0, total_transactions=0, top_products=[], low_stock_count=0, out_of_stock_count=0, recent_transactions=[])

    try:
        today_start = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + datetime.timedelta(days=1)

        # --- Fetch Sales and Transaction Counts (Unchanged) ---
        sales_response = supabase.table('transactions').select('total_amount').gte('date', today_start.isoformat()).lt('date', today_end.isoformat()).execute()
        total_sales = sum(txn['total_amount'] for txn in sales_response.data) if sales_response.data else 0

        txn_count_response = supabase.table('transactions').select('id', count='exact').gte('date', today_start.isoformat()).lt('date', today_end.isoformat()).execute()
        total_transactions = txn_count_response.count if hasattr(txn_count_response, 'count') else 0

        # --- Fetch Top Products (Unchanged) ---
        top_products_response = supabase.rpc('get_top_products', {'query_date': today_start.date().isoformat()}).execute()
        top_products = [{'name': p['name'], 'units': p['units']} for p in top_products_response.data] if top_products_response.data else []

        # --- Fetch Inventory Alerts (Unchanged) ---
        low_stock_response = supabase.table('products').select('id', count='exact').gt('stock', 0).lte('stock', 5).execute()
        low_stock_count = low_stock_response.count if hasattr(low_stock_response, 'count') else 0

        out_of_stock_response = supabase.table('products').select('id', count='exact').eq('stock', 0).execute()
        out_of_stock_count = out_of_stock_response.count if hasattr(out_of_stock_response, 'count') else 0

        # --- REMOVED 'get_recent_customers' RPC Call ---
        # recent_customers_response = supabase.rpc('get_recent_customers').execute()
        # recent_customers = [] # Set to empty or remove if not needed by template
        # if recent_customers_response.data:
        #     for customer in recent_customers_response.data:
        #         recent_customers.append({'name': customer.get('name', 'Unknown'), 'time_ago': time_ago(customer.get('latest_transaction'))})
        # --- END REMOVAL ---

        # --- MODIFIED: Fetch recent transactions WITHOUT 'customers(name)' ---
        # Also selecting 'created_by_user_id' to potentially display user later
        recent_transactions_response = supabase.table('transactions') \
            .select('id, transaction_code, date, total_amount, created_by_user_id') \
            .order('date', desc=True) \
            .limit(5) \
            .execute()
        # --- END MODIFICATION ---

        recent_transactions = []
        if recent_transactions_response.data:
            # TODO: OPTIONAL - Fetch user names for display if needed
            # user_ids = {txn['created_by_user_id'] for txn in recent_transactions_response.data if txn['created_by_user_id']}
            # user_map = {}
            # if user_ids:
            #     user_response = supabase.table('users').select('id, first_name, last_name').in_('id', list(user_ids)).execute()
            #     if user_response.data:
            #         user_map = {user['id']: f"{user['first_name']} {user['last_name']}" for user in user_response.data}

            for txn in recent_transactions_response.data:
                # creator_name = user_map.get(txn['created_by_user_id'], 'System/Unknown') # Example if fetching users
                recent_transactions.append({
                    'id': txn['transaction_code'],
                    'date': datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%Y %I:%M %p'),
                    # --- REMOVED 'customer_name' ---
                    # 'customer_name': txn['customers']['name'] if txn['customers'] else 'N/A',
                    # 'creator_name': creator_name, # Example if fetching users
                    'total': txn['total_amount']
                })

        return render_template(
            'dashboard.html',
            total_sales=total_sales,
            total_transactions=total_transactions,
            top_products=top_products,
            low_stock_count=low_stock_count,
            out_of_stock_count=out_of_stock_count,
            # --- REMOVED 'recent_customers' ---
            # recent_customers=recent_customers,
            recent_transactions=recent_transactions
        )

    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        # Log the specific error, but provide a generic message to the user
        flash(f"Error loading dashboard data. Please check server logs.", "danger")
        # Render fallback dashboard even if context processor also failed
        # Removed recent_customers from the fallback render_template context
        return render_template(
            'dashboard.html', total_sales=0, total_transactions=0, top_products=[],
            low_stock_count=0, out_of_stock_count=0, recent_transactions=[],
            error="Could not load dashboard data."
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


# --- ADD EMPLOYEES ROUTE ---
@app.route('/employees')
@login_required
def employees():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return redirect(url_for('dashboard'))

    # --- Authorization Check: Only Admins ---
    current_user_session = session.get('user')
    if not current_user_session or 'id' not in current_user_session:
        flash("Authentication error.", "danger")
        return redirect(url_for('login'))

    auth_user_id = current_user_session.get('id')
    user_is_admin = False
    try:
        response = supabase.table('users').select('role').eq('auth_user_id', auth_user_id).maybe_single().execute()
        if response.data and response.data.get('role') == 'admin':
            user_is_admin = True
    except Exception as e:
        print(f"ERROR: Could not perform role check query for auth_id {auth_user_id}: {e}")
        user_is_admin = False

    if not user_is_admin:
        flash("You do not have permission to view this page.", "warning")
        return redirect(url_for('dashboard'))
    # --- End Authorization Check ---

    # --- Fetch Employee Data and Activity using RPC ---
    try:
        # Call the database function
        response = supabase.rpc('get_employees_with_activity').execute() # Make sure function name matches exactly
        employees_data = response.data if response.data else []

        # The sorting (admins first, then name) is now handled by the database function

        return render_template('employees.html', employees=employees_data)

    except Exception as e:
        print(f"Error fetching employees list via RPC: {e}")
        # You might want to check if the error is specifically because the function doesn't exist
        if "relation \"get_employees_with_activity\" does not exist" in str(e):
             flash("Application error: Required database function is missing. Please contact support.", "danger")
        else:
            flash("Could not load employee data due to a server error.", "danger")
        return render_template('employees.html', employees=[]) # Render page with empty list on error
# --- END OF EMPLOYEES ROUTE ---

@app.template_filter('format_datetime')
def format_datetime_filter(value, format='medium'):
    if value is None:
        return ""
    # Ensure it's a datetime object
    if isinstance(value, str):
        try:
            # Attempt to parse ISO format with optional fraction and timezone
            value = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return value # Return original string if parsing fails
    if format == 'full':
        fmt = "EEEE, d. MMMM y 'at' HH:mm:ss zzzz"
    elif format == 'medium':
        fmt = "dd.MM.y HH:mm:ss"
    elif format == '%d %b %Y': # Custom format example
         fmt = 'dd MMM yyyy'
    else:
        fmt = format
    # Use UTC if timezone-naive, otherwise keep original timezone
    tz = datetime.timezone.utc if value.tzinfo is None else None
    return babel.dates.format_datetime(value, fmt, locale='en', tzinfo=tz)

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
    
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return redirect(url_for('dashboard'))
    
    current_auth_user_id = session.get('user', {}).get('id')
    if not current_auth_user_id:
        flash("Authentication error: Could not identify current user.", "danger")
        return redirect(url_for('login'))
    
    # Check if we're in edit mode (from GET parameter or form submission)
    edit_mode = request.args.get('edit', '').lower() == 'true' or request.form.get('edit_mode') == 'true'
    
    if request.method == 'POST' and edit_mode:
        # Get form data
        username = request.form.get('username')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        new_password = request.form.get('new_password')
        confirm_new_password = request.form.get('confirm_new_password')
        
        # Log the received data for debugging
        print(f"Profile update requested for user {current_auth_user_id}")
        print(f"Form data: username={username}, first_name={first_name}, last_name={last_name}")
        
        try:
            # First, check if the username is already taken by another user
            username_check = supabase.table('users') \
                .select('id') \
                .eq('username', username) \
                .neq('auth_user_id', current_auth_user_id) \
                .execute()
            
            if username_check.data and len(username_check.data) > 0:
                flash("Username is already taken. Please choose another.", "danger")
                return render_template('profile.html', profile={
                    'username': username,
                    'first_name': first_name,
                    'last_name': last_name,
                    'email': request.form.get('email'),
                    'role': request.form.get('role')
                }, edit_mode=True)
            
            # Import datetime correctly
            from datetime import datetime
            
            # Prepare the update data
            update_data = {
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'updated_at': datetime.now().isoformat()  # Fixed: Using datetime.now() instead of datetime.utcnow()
            }
            
            # Update the user profile in the database
            response = supabase.table('users') \
                .update(update_data) \
                .eq('auth_user_id', current_auth_user_id) \
                .execute()
            
            print(f"Supabase update response: {response}")
            
            # Handle password update if needed
            if new_password and new_password == confirm_new_password:
                # This depends on your auth setup - you may need to use a different method
                # For now, we'll just log that we would update the password
                print(f"Would update password for user {current_auth_user_id}")
                # Add your password update logic here
            
            flash("Profile updated successfully!", "success")
            return redirect(url_for('profile'))
        
        except Exception as e:
            print(f"Error updating profile for {current_auth_user_id}: {e}")
            flash("Error updating profile. Please try again.", "danger")
            return render_template('profile.html', profile={
                'username': username,
                'first_name': first_name,
                'last_name': last_name,
                'email': request.form.get('email'),
                'role': request.form.get('role')
            }, edit_mode=True)
    
    else:
        # GET request - show profile page
        try:
            response = supabase.table('users') \
                .select('id, email, username, first_name, last_name, role') \
                .eq('auth_user_id', current_auth_user_id) \
                .maybe_single() \
                .execute()
            
            if response.data:
                user_data = response.data
                user_data['created_at_formatted'] = "Account creation date not available"
                return render_template('profile.html', profile=user_data, edit_mode=edit_mode)
            else:
                print(f"WARNING: Profile data not found in public.users for authenticated user {current_auth_user_id}")
                flash("User profile data not found in the database. Please contact support.", "warning")
                return redirect(url_for('dashboard'))
        
        except Exception as e:
            print(f"Error fetching profile data for {current_auth_user_id}: {e}")
            flash("Could not load profile data due to a server error.", "danger")
            return redirect(url_for('dashboard'))
@app.route('/users/add', methods=['GET', 'POST'])
@login_required
def add_user():
    # Check DB connection
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return redirect(url_for('users'))
    
    # Authorization Check - Admin only
    current_user_session = session.get('user')
    if not current_user_session or 'id' not in current_user_session:
        flash("Authentication error.", "danger")
        return redirect(url_for('login'))
    
    auth_user_id = current_user_session.get('id')
    user_is_admin = False
    try:
        response = supabase.table('users').select('role').eq('auth_user_id', auth_user_id).maybe_single().execute()
        if response.data and response.data.get('role') == 'admin':
            user_is_admin = True
    except Exception as e:
        print(f"ERROR: Could not perform role check query for auth_id {auth_user_id}: {e}")
        user_is_admin = False
    
    if not user_is_admin:
        flash("You do not have permission to add users.", "warning")
        return redirect(url_for('dashboard'))
    
    # Form processing
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        username = request.form.get('username', '').strip().lower()
        role = request.form.get('role', 'user')  # Default to 'user' if not specified
        
        # Validation
        error = None
        if not email or not password or not confirm_password or not first_name or not last_name or not username:
            error = "All fields are required."
        elif not re.match(r"^\S+@\S+\.\S+$", email):
            error = "Invalid email format."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm_password:
            error = "Passwords do not match."
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            error = "Username can only contain letters, numbers, and underscores."
        elif len(username) < 3 or len(username) > 20:
            error = "Username must be between 3 and 20 characters."
        elif role not in ['user', 'admin']:
            error = "Invalid role selected."
        
        if error:
            flash(error, "danger")
            return render_template('add_user.html')
        
        try:
            # Check if email or username already exists
            email_check = supabase.table('users').select('id', count='exact').eq('email', email).execute()
            if email_check.count and email_check.count > 0:
                flash("Email is already registered.", "warning")
                return render_template('add_user.html')
            
            username_check = supabase.table('users').select('id', count='exact').eq('username', username).execute()
            if username_check.count and username_check.count > 0:
                flash("Username is already taken.", "warning")
                return render_template('add_user.html')
            
            # Create user in Supabase Auth
            auth_response =  supabase_admin.auth.admin.create_user({
                "email": email,
                "password": password,
                "email_confirm": True,  # Auto-confirm email
                "user_metadata": {
                    "role": role,
                    "first_name": first_name,
                    "last_name": last_name
                }
            })
            
            if not auth_response.user or not auth_response.user.id:
                flash("Failed to create user account.", "danger")
                return render_template('add_user.html')
            
            # Add user to public.users table
            user_profile_data = {
                'auth_user_id': str(auth_response.user.id),
                'email': email,
                'username': username,
                'role': role,
                'first_name': first_name,
                'last_name': last_name,
                'created_at': datetime.datetime.utcnow().isoformat()
            }
            
            insert_response = supabase.table('users').insert(user_profile_data).execute()
            
            if insert_response.data and len(insert_response.data) > 0:
                flash(f"User '{first_name} {last_name}' created successfully!", "success")
                return redirect(url_for('users'))
            else:
                # If user table insert fails, we should ideally delete the auth user too
                flash("User created but profile setup failed. Please check the system.", "warning")
                return redirect(url_for('users'))
        
        except Exception as e:
            print(f"Error creating user: {e}")
            flash(f"An error occurred while creating the user: {str(e)}", "danger")
            return render_template('add_user.html')
    
    # GET request - show the form
    return render_template('add_user.html')

# --- EDIT USER ROUTE ---
@app.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    # Check DB connection
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return redirect(url_for('users'))
    
    # Authorization Check - Admin only
    current_user_session = session.get('user')
    if not current_user_session or 'id' not in current_user_session:
        flash("Authentication error.", "danger")
        return redirect(url_for('login'))
    
    auth_user_id = current_user_session.get('id')
    user_is_admin = False
    try:
        response = supabase.table('users').select('role').eq('auth_user_id', auth_user_id).maybe_single().execute()
        if response.data and response.data.get('role') == 'admin':
            user_is_admin = True
    except Exception as e:
        print(f"ERROR: Could not perform role check query for auth_id {auth_user_id}: {e}")
        user_is_admin = False
    
    if not user_is_admin:
        flash("You do not have permission to edit users.", "warning")
        return redirect(url_for('dashboard'))
    
    # Get user data
    try:
        user_response = supabase.table('users').select('*').eq('id', user_id).maybe_single().execute()
        if not user_response.data:
            flash("User not found.", "danger")
            return redirect(url_for('users'))
        
        user_data = user_response.data
    except Exception as e:
        print(f"Error fetching user data: {e}")
        flash("Could not load user data.", "danger")
        return redirect(url_for('users'))
    
    # Form processing
    if request.method == 'POST':
        email = request.form.get('email')
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        username = request.form.get('username', '').strip().lower()
        role = request.form.get('role', 'user')
        
        # Validation
        error = None
        if not email or not first_name or not last_name or not username:
            error = "Name, email, and username fields are required."
        elif not re.match(r"^\S+@\S+\.\S+$", email):
            error = "Invalid email format."
        elif not re.match(r'^[a-zA-Z0-9_]+$', username):
            error = "Username can only contain letters, numbers, and underscores."
        elif len(username) < 3 or len(username) > 20:
            error = "Username must be between 3 and 20 characters."
        elif role not in ['user', 'admin']:
            error = "Invalid role selected."
        
        # Check for email uniqueness (excluding current user)
        if not error:
            try:
                email_check = supabase.table('users').select('id', count='exact').eq('email', email).neq('id', user_id).execute()
                if email_check.count and email_check.count > 0:
                    error = "Email is already used by another user."
            except Exception as e:
                print(f"Error checking uniqueness: {e}")
                error = "Could not validate email uniqueness."
        
        if error:
            flash(error, "danger")
            return render_template('edit_user.html', user=user_data)
        
        try:
            # Update user profile in public.users table
            update_data = {
                'email': email,
                'role': role,
                'first_name': first_name,
                'last_name': last_name,
                'updated_at': datetime.datetime.utcnow().isoformat()
            }
            
            update_response = supabase.table('users').update(update_data).eq('id', user_id).execute()
            
            if not update_response.data or len(update_response.data) == 0:
                flash("Failed to update user profile.", "danger")
                return render_template('edit_user.html', user=user_data)
            
            flash(f"User '{first_name} {last_name}' updated successfully!", "success")
            return redirect(url_for('users'))
            
        except Exception as e:
            print(f"Error updating user: {e}")
            flash(f"An error occurred while updating the user: {str(e)}", "danger")
            return render_template('edit_user.html', user=user_data)
    
    # GET request - show the form with user data
    return render_template('edit_user.html', user=user_data)   


# --- DELETE USER ROUTE ---
@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    # Check DB connection
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return redirect(url_for('users'))
    
    # Authorization Check - Admin only
    current_user_session = session.get('user')
    if not current_user_session or 'id' not in current_user_session:
        flash("Authentication error.", "danger")
        return redirect(url_for('login'))
    
    auth_user_id = current_user_session.get('id')
    user_is_admin = False
    try:
        response = supabase.table('users').select('role').eq('auth_user_id', auth_user_id).maybe_single().execute()
        if response.data and response.data.get('role') == 'admin':
            user_is_admin = True
    except Exception as e:
        print(f"ERROR: Could not perform role check query for auth_id {auth_user_id}: {e}")
        user_is_admin = False
    
    if not user_is_admin:
        flash("You do not have permission to delete users.", "warning")
        return redirect(url_for('dashboard'))
    
    # Get user to be deleted
    try:
        user_response = supabase.table('users').select('*').eq('id', user_id).maybe_single().execute()
        if not user_response.data:
            flash("User not found.", "danger")
            return redirect(url_for('users'))
        
        user_data = user_response.data
        
        # Check if trying to delete self
        if user_data.get('auth_user_id') == auth_user_id:
            flash("You cannot delete your own account.", "warning")
            return redirect(url_for('users'))
        
        # Delete from public.users table first
        delete_response = supabase.table('users').delete().eq('id', user_id).execute()
        
        # If successful and we have auth_user_id, delete from Auth as well
        if delete_response.data and len(delete_response.data) > 0 and user_data.get('auth_user_id'):
            try:
                # Delete from Auth
                supabase_admin.auth.admin.delete_user(user_data.get('auth_user_id'))
                flash(f"User '{user_data.get('first_name')} {user_data.get('last_name')}' deleted successfully.", "success")
            except Exception as auth_err:
                print(f"User deleted from database but error removing from Auth: {auth_err}")
                flash("User removed from system but Auth cleanup may be incomplete.", "warning")
        else:
            flash("User deleted successfully.", "success")
        
        return redirect(url_for('users'))
        
    except Exception as e:
        print(f"Error deleting user: {e}")
        flash("An error occurred while deleting the user.", "danger")
        return redirect(url_for('users'))     
    
# Get all products
@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        response = supabase.table('products') \
            .select('id, name, sku, category, price, stock, status, description, created_at, updated_at') \
            .order('name') \
            .execute()
        
        products = []
        if response.data:
            for product in response.data:
                products.append({
                    'id': product['id'],
                    'name': product['name'],
                    'sku': product['sku'],
                    'category': product['category'],
                    'price': product['price'],
                    'stock': product['stock'],
                    'status': 'active' if product['status'] else 'inactive',
                    'description': product['description'],
                    'created_at': product['created_at'],
                    'updated_at': product['updated_at']
                })
        
        return jsonify(products)
    except Exception as e:
        print(f"Error fetching products: {e}")
        return jsonify({"error": "Failed to fetch products"}), 500

# Get a single product
@app.route('/api/products/<int:product_id>', methods=['GET'])
@login_required
def get_product(product_id):
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        response = supabase.table('products') \
            .select('id, name, sku, category, price, stock, status, description, created_at, updated_at') \
            .eq('id', product_id) \
            .maybe_single() \
            .execute()
        
        if not response.data:
            return jsonify({"error": "Product not found"}), 404
            
        product = {
            'id': response.data['id'],
            'name': response.data['name'],
            'sku': response.data['sku'],
            'category': response.data['category'],
            'price': response.data['price'],
            'stock': response.data['stock'],
            'status': 'active' if response.data['status'] else 'inactive',
            'description': response.data['description'],
            'created_at': response.data['created_at'],
            'updated_at': response.data['updated_at']
        }
        
        return jsonify(product)
    except Exception as e:
        print(f"Error fetching product: {e}")
        return jsonify({"error": "Failed to fetch product"}), 500

# Update the create_product endpoint
@app.route('/api/products', methods=['POST'])
@login_required
def create_product():
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        # Handle form data (including file upload)
        name = request.form.get('name')
        sku = request.form.get('sku')
        category = request.form.get('category')
        price = request.form.get('price')
        stock = request.form.get('stock')
        status = request.form.get('status')
        description = request.form.get('description')
        
        # Validate required fields
        if not name or not category or not price or not stock:
            return jsonify({"error": "Missing required fields"}), 400

        # Handle file upload
        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and allowed_file(file.filename):
                # Generate a unique filename
                filename = f"{uuid.uuid4()}_{secure_filename(file.filename)}"
                
                # Upload to Supabase Storage
                try:
                    # First ensure the bucket exists
                    try:
                        supabase.storage.create_bucket("product-images", {
                            "public": True,
                            "allowed_mime_types": ["image/*"],
                            "file_size_limit": "50MB"  # Adjust as needed
                        })
                    except Exception as e:
                        # Bucket may already exist
                        pass
                    
                    # Upload the file
                    file_bytes = file.read()
                    res = supabase.storage.from_("product-images").upload(
                        file=file_bytes,
                        path=filename,
                        file_options={"content-type": file.content_type}
                    )
                    
                    # Get public URL
                    image_url = supabase.storage.from_("product-images").get_public_url(filename)
                except Exception as upload_error:
                    print(f"Error uploading image: {upload_error}")
                    # Continue without image if upload fails

        status_bool = status == 'active'
        
        # Create product data dict
        product_data = {
            'name': name,
            'sku': sku,
            'category': category,
            'price': float(price),
            'stock': int(stock),
            'status': status_bool,
            'description': description,
            'image_url': image_url  # Add image URL to product data
        }

        # Insert into database
        response = supabase.table('products').insert(product_data).execute()
        
        if not response.data or len(response.data) == 0:
            return jsonify({"error": "Failed to create product"}), 500
            
        new_product = {
            'id': response.data[0]['id'],
            'name': response.data[0]['name'],
            'sku': response.data[0]['sku'],
            'category': response.data[0]['category'],
            'price': response.data[0]['price'],
            'stock': response.data[0]['stock'],
            'status': 'active' if response.data[0]['status'] else 'inactive',
            'description': response.data[0]['description'],
            'image_url': response.data[0].get('image_url'),
            'created_at': response.data[0]['created_at'],
            'updated_at': response.data[0]['updated_at']
        }
        
        return jsonify(new_product), 201
    except Exception as e:
        print(f"Error creating product: {e}")
        return jsonify({"error": "Failed to create product"}), 500

# Update a product
@app.route('/api/products/<int:product_id>', methods=['PUT'])
@login_required
def update_product(product_id):
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    data = request.json
    if not data:
        return jsonify({"error": "No data provided"}), 400

    try:
        status_bool = True if data.get('status') == 'active' else False
        
        response = supabase.table('products') \
            .update({
                'name': data.get('name'),
                'sku': data.get('sku'),
                'category': data.get('category'),
                'price': data.get('price'),
                'stock': data.get('stock'),
                'status': status_bool,
                'description': data.get('description'),
                'updated_at': datetime.datetime.utcnow().isoformat()
            }) \
            .eq('id', product_id) \
            .execute()
        
        if not response.data or len(response.data) == 0:
            return jsonify({"error": "Product not found"}), 404
            
        updated_product = {
            'id': response.data[0]['id'],
            'name': response.data[0]['name'],
            'sku': response.data[0]['sku'],
            'category': response.data[0]['category'],
            'price': response.data[0]['price'],
            'stock': response.data[0]['stock'],
            'status': 'active' if response.data[0]['status'] else 'inactive',
            'description': response.data[0]['description'],
            'created_at': response.data[0]['created_at'],
            'updated_at': response.data[0]['updated_at']
        }
        
        return jsonify(updated_product)
    except Exception as e:
        print(f"Error updating product: {e}")
        return jsonify({"error": "Failed to update product"}), 500

# Delete a product
@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        # First check if product exists
        check_response = supabase.table('products') \
            .select('id') \
            .eq('id', product_id) \
            .maybe_single() \
            .execute()
            
        if not check_response.data:
            return jsonify({"error": "Product not found"}), 404
        
        # Delete the product
        delete_response = supabase.table('products') \
            .delete() \
            .eq('id', product_id) \
            .execute()
            
        return jsonify({"message": "Product deleted successfully"}), 200
    except Exception as e:
        print(f"Error deleting product: {e}")
        return jsonify({"error": "Failed to delete product"}), 500        

@app.route('/api/products/<int:product_id>/image', methods=['POST'])
@login_required
def upload_product_image(product_id):
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    try:
        # Check if product exists
        product_response = supabase.table('products').select('id').eq('id', product_id).maybe_single().execute()
        if not product_response.data:
            return jsonify({"error": "Product not found"}), 404

        # Check if file was uploaded
        if 'image' not in request.files:
            return jsonify({"error": "No image file provided"}), 400

        file = request.files['image']
        if not file or file.filename == '':
            return jsonify({"error": "No selected file"}), 400

        if not allowed_file(file.filename):
            return jsonify({"error": "File type not allowed"}), 400

        # Generate a unique filename
        filename = f"product_{product_id}_{uuid.uuid4()}{secure_filename(file.filename)}"

        # Upload to Supabase Storage
        try:
            # Ensure the bucket exists
            try:
                supabase.storage.create_bucket("product-images", {
                    "public": True,
                    "allowed_mime_types": ["image/*"],
                    "file_size_limit": "50MB"
                })
            except Exception as e:
                # Bucket may already exist
                pass
            
            # Upload the file
            file_bytes = file.read()
            res = supabase.storage.from_("product-images").upload(
                file=file_bytes,
                path=filename,
                file_options={"content-type": file.content_type}
            )
            
            # Get public URL
            image_url = supabase.storage.from_("product-images").get_public_url(filename)

            # Update product with image URL
            update_response = supabase.table('products').update({
                'image_url': image_url,
                'updated_at': datetime.datetime.utcnow().isoformat()
            }).eq('id', product_id).execute()

            if not update_response.data or len(update_response.data) == 0:
                return jsonify({"error": "Failed to update product image"}), 500

            return jsonify({
                "message": "Image uploaded successfully",
                "imageUrl": image_url
            }), 200

        except Exception as upload_error:
            print(f"Error uploading image: {upload_error}")
            return jsonify({"error": "Failed to upload image"}), 500

    except Exception as e:
        print(f"Error in image upload endpoint: {e}")
        return jsonify({"error": "Internal server error"}), 500          

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