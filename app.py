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
from dateutil.relativedelta import relativedelta 
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

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session or 'user' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login', next=request.url))
        # Refresh user role from DB on each request if needed, or rely on context_processor
        return f(*args, **kwargs)
    return decorated_function    
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

@app.route('/dashboard')
@login_required
def dashboard():
    if not check_supabase():
        flash("Application error: Database connection failed.", "danger")
        return render_template('dashboard.html', error='Database connection failed.', total_sales=0, total_transactions=0, top_products=[], low_stock_count=0, out_of_stock_count=0, recent_transactions=[])

    try:
        today_start = datetime.datetime.now(datetime.timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + datetime.timedelta(days=1)

        sales_response = supabase.table('transactions').select('total_amount').gte('date', today_start.isoformat()).lt('date', today_end.isoformat()).execute()
        total_sales = sum(txn['total_amount'] for txn in sales_response.data) if sales_response.data else 0

        txn_count_response = supabase.table('transactions').select('id', count='exact').gte('date', today_start.isoformat()).lt('date', today_end.isoformat()).execute()
        total_transactions = txn_count_response.count if hasattr(txn_count_response, 'count') else 0

        top_products_response = supabase.rpc('get_top_products', {'query_date': today_start.date().isoformat()}).execute()
        top_products = [{'name': p['name'], 'units': p['units']} for p in top_products_response.data] if top_products_response.data else []

        low_stock_response = supabase.table('products').select('id', count='exact').gt('stock', 0).lte('stock', 5).execute()
        low_stock_count = low_stock_response.count if hasattr(low_stock_response, 'count') else 0

        out_of_stock_response = supabase.table('products').select('id', count='exact').eq('stock', 0).execute()
        out_of_stock_count = out_of_stock_response.count if hasattr(out_of_stock_response, 'count') else 0
        
        recent_transactions_data = []
        try:
            recent_transactions_response = supabase.table('transactions') \
                .select('''
                    transaction_code,
                    date,
                    total_amount,
                    customer:customers ( name ),
                    items:transaction_items ( products(name), quantity, price )
                ''') \
                .order('date', desc=True) \
                .limit(5) \
                .execute()

            if recent_transactions_response.data:
                for txn in recent_transactions_response.data:
                    customer_info = txn.get('customer')
                    customer_name = customer_info['name'] if customer_info else 'Walk-in/N/A'
                    
                    recent_transactions_data.append({
                        'transaction_code': txn['transaction_code'],
                        'date_formatted': datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%y %I:%M %p'),
                        'customer_name': customer_name,
                        'total': txn['total_amount']
                        # items are not typically displayed in dashboard summary
                    })
        except Exception as e_rt:
            print(f"Error fetching recent transactions for dashboard: {e_rt}")
            # flash("Could not load recent transactions.", "warning") # Optional

        return render_template(
            'dashboard.html',
            total_sales=total_sales,
            total_transactions=total_transactions,
            top_products=top_products,
            low_stock_count=low_stock_count,
            out_of_stock_count=out_of_stock_count,
            recent_transactions=recent_transactions_data
        )

    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        flash(f"Error loading dashboard data.", "danger")
        return render_template('dashboard.html', total_sales=0, total_transactions=0, top_products=[], low_stock_count=0, out_of_stock_count=0, recent_transactions=[], error="Could not load dashboard data.")



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

# app.py
# app.py

@app.route('/transactions')
@login_required
def transactions():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return render_template('transactions.html', transactions=[])
    
    try:
        # Get filter parameters from query string
        start_date_str = request.args.get('start_date')
        end_date_str = request.args.get('end_date')
        search_term = request.args.get('search_term', '').strip().lower() # For customer name or txn code

        query = supabase.table('transactions') \
            .select('''
                id, 
                transaction_code, 
                date, 
                total_amount, 
                payment_method,
                notes,
                customer:customers ( id, name ), 
                employee_creator:created_by_user_id ( id, first_name, last_name ),
                items:transaction_items ( products (name), quantity, price )
            ''')

        # Apply date filters
        if start_date_str:
            try:
                start_date_dt = datetime.datetime.strptime(start_date_str, '%Y-%m-%d').replace(tzinfo=datetime.timezone.utc)
                query = query.gte('date', start_date_dt.isoformat())
            except ValueError:
                flash("Invalid 'From Date' format. Please use YYYY-MM-DD.", "warning")
        
        if end_date_str:
            try:
                # To make end_date inclusive, filter up to the end of that day
                end_date_dt = (datetime.datetime.strptime(end_date_str, '%Y-%m-%d') + datetime.timedelta(days=1) - datetime.timedelta(seconds=1)).replace(tzinfo=datetime.timezone.utc)
                query = query.lte('date', end_date_dt.isoformat())
            except ValueError:
                flash("Invalid 'To Date' format. Please use YYYY-MM-DD.", "warning")
        
        # Note: Direct filtering on joined customer name like `customer:name.ilike.%{search_term}%`
        # is not straightforward with the basic Python client query builder for arbitrary text.
        # This often requires an RPC or view for efficient server-side searching on related fields.
        # The current implementation will filter by customer name in Python after fetching.
        # If search_term is a transaction code, we can filter that at DB level.
        if search_term and search_term.upper().startswith("TXN-"):
             query = query.ilike('transaction_code', f"%{search_term}%")
        
        response = query.order('date', desc=True).execute()
        
        raw_transactions = response.data or []
        transactions_data = []

        for txn in raw_transactions:
            customer_info = txn.get('customer')
            customer_name = customer_info['name'] if customer_info else 'Walk-in/N/A'
            
            # Python-side filtering for customer name if search_term is not a transaction code
            if search_term and not search_term.upper().startswith("TXN-"):
                if search_term not in customer_name.lower():
                    continue # Skip this transaction

            employee_info = txn.get('employee_creator')
            employee_name = f"{employee_info['first_name']} {employee_info['last_name']}" if employee_info else 'System/Unknown'
            
            items_for_receipt = []
            if txn.get('items'):
                for item in txn['items']:
                    product_name = item['products']['name'] if item.get('products') else 'Unknown Item'
                    items_for_receipt.append({
                        'name': product_name,
                        'quantity': item['quantity'],
                        'price': item['price']
                    })

            transactions_data.append({
                'id': txn['id'],
                'transaction_code': txn['transaction_code'],
                'date': datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%Y %I:%M %p'),
                'customer_name': customer_name,
                'employee_name': employee_name,
                'total': txn['total_amount'],
                'payment_method': txn.get('payment_method', 'N/A'),
                'items': items_for_receipt # For receipt modal
            })
        
        return render_template('transactions.html', 
                               transactions=transactions_data,
                               start_date_filter=start_date_str, # Pass back for form repopulation
                               end_date_filter=end_date_str,
                               search_term_filter=request.args.get('search_term', '')) # Use original search_term
    
    except Exception as e:
        print(f"Error fetching transactions: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
        flash("Could not load transaction data. Check server logs for details.", "danger")
        return render_template('transactions.html', transactions=[],
                               start_date_filter=request.args.get('start_date'),
                               end_date_filter=request.args.get('end_date'),
                               search_term_filter=request.args.get('search_term'))

@app.route('/transactions/edit/<int:txn_id>', methods=['GET', 'POST'])
@login_required
def edit_transaction(txn_id):
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return redirect(url_for('transactions'))
    
    # Only allow admins to edit transactions (using role from user profile table)
    user_profile_role = None
    current_auth_id = session.get('user', {}).get('id')
    if current_auth_id:
        try:
            # Query your actual user profile table ('users' or 'employees')
            role_res = supabase.table('users').select('role').eq('auth_user_id', current_auth_id).maybe_single().execute()
            if role_res.data:
                user_profile_role = role_res.data['role']
        except Exception as e_role:
            print(f"Error fetching user role for edit_transaction: {e_role}")

    if user_profile_role != 'admin':
        flash("You don't have permission to edit transactions.", "danger")
        return redirect(url_for('transactions'))
    
    if request.method == 'POST':
        try:
            customer_id_form = request.form.get('customer_id')
            payment_method = request.form.get('payment_method')
            notes = request.form.get('notes')
            
            update_data = {
                'customer_id': int(customer_id_form) if customer_id_form else None, # Ensure None if empty
                'payment_method': payment_method,
                'notes': notes,
                'updated_at': datetime.datetime.now(datetime.timezone.utc).isoformat()
            }
            
            response = supabase.table('transactions') \
                .update(update_data) \
                .eq('id', txn_id) \
                .execute()
            
            if response.data: # supabase-py update returns list of updated records
                flash("Transaction updated successfully!", "success")
            else: # No data returned, likely means no rows matched or RLS issue not raising an exception
                flash("Failed to update transaction or no changes made.", "warning") # More nuanced message
            return redirect(url_for('transactions'))
        
        except Exception as e:
            print(f"Error updating transaction {txn_id}: {type(e).__name__} - {e}")
            import traceback
            traceback.print_exc()
            flash("An error occurred while updating the transaction.", "danger")
            # It's better to redirect to the edit page again on POST failure to show form with errors,
            # but for simplicity, redirecting to list for now.
            return redirect(url_for('edit_transaction', txn_id=txn_id)) 
    
    # GET request - show edit form
    try:
        txn_response = supabase.table('transactions') \
            .select('''
                *, 
                customers:customer_id (id, name), 
                users:created_by_user_id (first_name, last_name)
            ''') \
            .eq('id', txn_id) \
            .maybe_single() \
            .execute()
        
        if not txn_response.data:
            flash("Transaction not found.", "danger")
            return redirect(url_for('transactions'))
        
        # Format date for display if needed by template (though template does it now)
        # txn_response.data['date_formatted'] = datetime.datetime.fromisoformat(txn_response.data['date'].replace('Z', '+00:00')).strftime('%d/%m/%Y %I:%M %p')

        customers_response = supabase.table('customers') \
            .select('id, name') \
            .order('name') \
            .execute()
        
        return render_template('edit_transaction.html', 
                             transaction=txn_response.data,
                             customers=customers_response.data or [])
    
    except Exception as e:
        print(f"Error fetching transaction data for edit {txn_id}: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
        flash("Could not load transaction data for editing.", "danger")
        return redirect(url_for('transactions'))
# app.py

@app.route('/api/transaction/<int:txn_id>/receipt_details')
@login_required
def transaction_receipt_details(txn_id):
    if not check_supabase():
        return jsonify({"error": "Database connection failed"}), 500
    try:
        response = supabase.table('transactions') \
            .select('''
                transaction_code,
                date,
                total_amount,
                payment_method,
                notes,
                customer:customers ( name ),
                employee_creator:created_by_user_id ( first_name, last_name ),
                items:transaction_items ( quantity, price, product:products (name) )
            ''') \
            .eq('id', txn_id) \
            .maybe_single() \
            .execute()

        if not response.data:
            return jsonify({"error": "Transaction not found"}), 404

        txn = response.data
        customer_info = txn.get('customer')
        customer_name = customer_info['name'] if customer_info else 'Walk-in/N/A'
        
        employee_info = txn.get('employee_creator')
        employee_name = f"{employee_info['first_name']} {employee_info['last_name']}" if employee_info else 'System'

        items_list = []
        if txn.get('items'):
            for item_data in txn['items']:
                product_info = item_data.get('product')
                items_list.append({
                    "product_name": product_info['name'] if product_info else "Unknown Item",
                    "quantity": item_data['quantity'],
                    "price": item_data['price']
                })
        
        receipt_data = {
            "transaction_code": txn['transaction_code'],
            "date": txn['date'], # Will be formatted by JS
            "total_amount": txn['total_amount'],
            "payment_method": txn.get('payment_method', 'N/A'),
            "notes": txn.get('notes', ''),
            "customer_name": customer_name,
            "employee_name": employee_name,
            "items": items_list
        }
        return jsonify(receipt_data)

    except Exception as e:
        print(f"Error fetching receipt details for txn_id {txn_id}: {e}")
        return jsonify({"error": "Could not load receipt details"}), 500
# --- ADD EMPLOYEES ROUTE ---
# app.py
# ... (other imports)

def generate_transaction_code():
    # Simple unique code: timestamp + random part
    return f"TXN-{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:6].upper()}"

# Helper to get current user's DB ID (from 'users' table)
def get_current_user_db_id_from_session(): # Renamed for clarity
    auth_user_id = session.get('user', {}).get('id') # This is auth.users.id (UUID)
    if not auth_user_id or not check_supabase():
        return None
    try:
        # Query your user profile table (e.g., 'users' or 'employees')
        # to get its integer primary key if that's what created_by_user_id expects
        user_profile_response = supabase.table('users').select('id').eq('auth_user_id', auth_user_id).maybe_single().execute()
        if user_profile_response.data:
            return user_profile_response.data['id'] # This is users.id (int4)
        return None
    except Exception as e:
        print(f"Error fetching user DB ID for auth_id {auth_user_id}: {e}")
        return None

@app.route('/transactions/add', methods=['GET', 'POST'])
@login_required
def add_transaction():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return redirect(url_for('transactions'))

    form_data_on_error = {} # To repopulate form on POST error

    if request.method == 'POST':
        # This section retains the detailed POST logic from our previous discussions
        # for creating the transaction, items, handling customer creation, and stock updates.
        # It's extensive, so I'll use a placeholder here, assuming you have that full logic.
        # Ensure it handles errors by setting flash messages and re-rendering the template
        # by falling through to the GET logic below, passing form_data_on_error.
        try:
            # --- Start of POST Logic (from previous full example) ---
            customer_selection_type = request.form.get('customer_selection_type')
            customer_id_form = request.form.get('customer_id')
            new_customer_name = request.form.get('new_customer_name_field', '').strip() # Match name in HTML
            payment_method = request.form.get('payment_method')
            notes = request.form.get('notes')
            amount_paid_str = request.form.get('amount_paid')

            product_ids = request.form.getlist('product_id[]')
            quantities = request.form.getlist('quantity[]')

            # Store form data to pass back in case of error during POST processing
            form_data_on_error = {
                'selected_customer_id': customer_id_form,
                'new_customer_name_text': new_customer_name, # Use 'new_customer_name_field' if that's the HTML name
                'selected_payment_method': payment_method,
                'notes_text': notes,
                'amount_paid_val': amount_paid_str,
                # Storing selected products/quantities for repopulation is complex,
                # usually users re-select them after an error.
            }
            
            final_customer_id = None
            if customer_selection_type == 'existing' and customer_id_form:
                final_customer_id = int(customer_id_form)
            elif customer_selection_type == 'new' and new_customer_name:
                existing_customer_res = supabase.table('customers').select('id').eq('name', new_customer_name).maybe_single().execute()
                if existing_customer_res.data:
                    final_customer_id = existing_customer_res.data['id']
                    flash(f"Using existing customer '{new_customer_name}'.", "info")
                else:
                    new_cust_payload = {'name': new_customer_name} 
                    # Add phone/email here if you collect them in the form for new customers
                    # new_cust_payload['phone_number'] = request.form.get('new_customer_phone') 
                    created_customer_res = supabase.table('customers').insert(new_cust_payload).execute()
                    if created_customer_res.data:
                        final_customer_id = created_customer_res.data[0]['id']
                        flash(f"New customer '{new_customer_name}' created and selected.", "success")
                    else:
                        flash("Failed to create new customer record.", "danger")
                        raise ValueError("New customer creation failed.") # Trigger re-render
            # If 'walk_in' or no specific customer action, final_customer_id remains None

            if not product_ids or not any(pid for pid in product_ids if pid):
                flash("Please select at least one product.", "danger")
                raise ValueError("No products selected")

            try:
                amount_paid = float(amount_paid_str) if amount_paid_str else 0.0
                if amount_paid < 0:
                    flash("Amount paid cannot be negative.", "danger")
                    raise ValueError("Negative amount paid")
            except (ValueError, TypeError):
                flash("Invalid amount paid. Please enter a valid number.", "danger")
                raise ValueError("Invalid amount paid value")

            transaction_items_to_insert = []
            grand_total = 0.0
            product_stock_updates = []

            for i, product_id_str in enumerate(product_ids):
                if not product_id_str: continue
                product_id = int(product_id_str)
                quantity = int(quantities[i])

                if quantity <= 0:
                    flash(f"Quantity for product ID {product_id} must be positive.", "danger")
                    raise ValueError("Invalid quantity")

                product_info_res = supabase.table('products').select('price, stock, name').eq('id', product_id).eq('status', True).maybe_single().execute()
                if not product_info_res.data:
                    flash(f"Active product with ID {product_id} not found or out of stock.", "danger")
                    raise ValueError("Product not found or OOS")
                
                product_price = float(product_info_res.data['price'])
                current_stock = int(product_info_res.data['stock'])
                product_name = product_info_res.data['name']

                if quantity > current_stock:
                    flash(f"Not enough stock for '{product_name}'. Available: {current_stock}, Requested: {quantity}.", "danger")
                    raise ValueError("Insufficient stock")

                item_total = product_price * quantity
                grand_total += item_total
                transaction_items_to_insert.append({'product_id': product_id, 'quantity': quantity, 'price': product_price})
                product_stock_updates.append({'id': product_id, 'new_stock': current_stock - quantity})

            created_by_db_user_id = get_current_user_db_id_from_session()
            if created_by_db_user_id is None:
                flash("Could not identify processing employee. Please log in again.", "danger")
                raise ValueError("Employee not identified")
            
            balance_due = grand_total - amount_paid

            main_transaction_payload = {
                'transaction_code': generate_transaction_code(),
                'date': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'total_amount': grand_total,
                'customer_id': final_customer_id,
                'payment_method': payment_method,
                'notes': notes,
                'created_by_user_id': created_by_db_user_id,
                'amount_paid': amount_paid,
                'balance_due': balance_due 
            }
            
            inserted_txn_res = supabase.table('transactions').insert(main_transaction_payload).execute()

            if not inserted_txn_res.data or len(inserted_txn_res.data) == 0:
                flash("Failed to create main transaction record.", "danger")
                raise Exception("Transaction insert failed") # More generic exception if specific value error not appropriate

            new_transaction_id = inserted_txn_res.data[0]['id']

            for item in transaction_items_to_insert: item['transaction_id'] = new_transaction_id
            
            if transaction_items_to_insert: # Only insert if there are items
                items_insert_res = supabase.table('transaction_items').insert(transaction_items_to_insert).execute()
                if not items_insert_res.data: # Check if data is empty after insert
                    flash(f"Transaction #{inserted_txn_res.data[0]['transaction_code']} created, but failed to record items! Review manually.", "danger")
            
            # For atomicity, an RPC is highly recommended for transaction + items + stock updates.
            for stock_update in product_stock_updates:
                stock_update_response = supabase.table('products').update({'stock': stock_update['new_stock']}).eq('id', stock_update['id']).execute()
                if not stock_update_response.data:
                     flash(f"Warning: Stock for product ID {stock_update['id']} might not have updated correctly.", "warning")


            flash(f"Transaction #{inserted_txn_res.data[0]['transaction_code']} created successfully!", "success")
            return redirect(url_for('transactions'))

        except ValueError as ve: # Catch our specific validation ValueErrors
            # Flash message should have been set before raising ValueError
            # The request will fall through to the GET rendering part below
            # which re-fetches data for the form.
            # Pass form_data_on_error to the template context when re-rendering.
            request.form_data_on_error = form_data_on_error # Attach to request to pass it down
        except Exception as e:
            print(f"Error adding transaction: {type(e).__name__} - {e}")
            import traceback
            traceback.print_exc()
            flash("An unexpected error occurred while adding the transaction. Please check details and try again.", "danger")
            request.form_data_on_error = form_data_on_error # Attach to request

    # --- GET request logic OR if POST had an error and fell through ---
    # Retrieve form_data from request if it was set by POST error handling
    current_form_data = getattr(request, 'form_data_on_error', {})

    try:
        customers_resp = supabase.table('customers').select('id, name, phone_number').order('name').execute()
        
        # Fetch products with their category object (which includes id and name) for JS data
        products_resp = supabase.table('products') \
            .select('id, name, price, stock, category_id, category:categories(id, name)') \
            .eq('status', True) \
            .gt('stock', 0) \
            .order('name') \
            .execute()
        
        # Fetch all distinct categories for the category filter dropdown
        all_categories_resp = supabase.table('categories').select('id, name').order('name').execute()
        
        products_for_js = []
        if products_resp.data:
            for p in products_resp.data:
                # 'category' here will be the joined object {id: X, name: Y} or None
                cat_info = p.get('category') 
                products_for_js.append({
                    'id': p['id'],
                    'name': p['name'],
                    'price': p['price'],
                    'stock': p.get('stock', 0),
                    'category_id': cat_info['id'] if cat_info else p.get('category_id'), # Use direct or from joined
                    # category_name is not strictly needed if JS filters by ID, but good for debugging
                    # 'category_name': cat_info['name'] if cat_info else 'Uncategorized' 
                })

    except Exception as e_fetch:
        print(f"Error fetching data for add transaction form: {type(e_fetch).__name__} - {e_fetch}")
        flash("Could not load essential data for the transaction form. Please try again later.", "warning")
        customers_resp = {'data': []} # Default to empty list on error
        products_for_js = []
        all_categories_resp = {'data': []}

    return render_template('add_transaction.html', 
                         customers=customers_resp.data or [], 
                         products_json_for_js=products_for_js, # This is used by JS data attribute
                         all_categories=all_categories_resp.data or [], # For the category filter dropdown
                         form_data=current_form_data) # Pass form data for repopulation

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


@app.route('/customers')
@login_required
def customers_page(): # Renamed to avoid conflict with any 'customers' variable
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return render_template('customers.html', customers=[])
    try:
        response = supabase.table('customers') \
            .select('id, name, phone_number, email, address, created_at') \
            .order('name', desc=False) \
            .execute()
        
        return render_template('customers.html', customers=response.data or [])
    except Exception as e:
        print(f"Error fetching customers: {e}")
        flash("Could not load customer data.", "danger")
        return render_template('customers.html', customers=[])

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


@app.route('/api/reports/<period>', methods=['GET'])
@login_required
def generate_report_api(period):
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    today = datetime.datetime.now(datetime.timezone.utc).date() # Use timezone-aware
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

    start_datetime = datetime.datetime.combine(start_date, datetime.time.min, tzinfo=datetime.timezone.utc)
    end_datetime = datetime.datetime.combine(end_date, datetime.time.max, tzinfo=datetime.timezone.utc)

    try:
        transactions_response = supabase.table('transactions') \
            .select('date, transaction_code, total_amount, payment_method, customer:customers(name)') \
            .gte('date', start_datetime.isoformat()) \
            .lte('date', end_datetime.isoformat()) \
            .order('date') \
            .execute()
        transactions_for_report = transactions_response.data if transactions_response.data else []

        buffer = io.BytesIO()
        p_canvas = canvas.Canvas(buffer, pagesize=letter) # Renamed to avoid conflict
        width, height = letter
        p_canvas.setFont('Helvetica-Bold', 16)
        p_canvas.drawString(50, height - 50, "Bash Merchandise Management")
        p_canvas.setFont('Helvetica', 14)
        p_canvas.drawString(50, height - 70, title)
        p_canvas.setFont('Helvetica', 10)
        p_canvas.line(50, height - 80, width - 50, height - 80)

        y_position = height - 100
        # Adjusted X positions for more columns potentially
        headers = ["Date", "Transaction ID", "Customer", "Payment", "Amount (UGX)"]
        x_positions = [50, 150, 270, 380, 480] 
        p_canvas.setFont('Helvetica-Bold', 10)
        for i, header in enumerate(headers): p_canvas.drawString(x_positions[i], y_position, header)

        y_position -= 15
        p_canvas.setFont('Helvetica', 9)
        total_report_amount = 0

        for txn in transactions_for_report:
            if y_position < 60: # New page if not enough space
                p_canvas.showPage()
                p_canvas.setFont('Helvetica-Bold', 10)
                y_position = height - 100 # Reset y_position for new page
                for i, header in enumerate(headers): p_canvas.drawString(x_positions[i], y_position, header)
                y_position -= 15
                p_canvas.setFont('Helvetica', 9)

            date_str = datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%y %H:%M')
            txn_id_str = txn['transaction_code']
            customer_info = txn.get('customer')
            customer_name_str = customer_info['name'] if customer_info else 'N/A'
            payment_method_str = txn.get('payment_method', 'N/A')
            amount_val = txn['total_amount']
            total_report_amount += amount_val

            p_canvas.drawString(x_positions[0], y_position, date_str)
            p_canvas.drawString(x_positions[1], y_position, txn_id_str)
            p_canvas.drawString(x_positions[2], y_position, customer_name_str)
            p_canvas.drawString(x_positions[3], y_position, payment_method_str)
            
            try: amount_str_pdf = f"{float(amount_val):,.0f}"
            except: amount_str_pdf = "Invalid"
            p_canvas.drawRightString(x_positions[4] + 70, y_position, amount_str_pdf) # Right align amount

            y_position -= 15

        p_canvas.line(50, y_position + 5, width - 50, y_position + 5)
        y_position -= 10
        p_canvas.setFont('Helvetica-Bold', 10)
        summary_x_start = x_positions[3] # Align summary labels under "Payment"
        p_canvas.drawString(summary_x_start, y_position, "Total Transactions:")
        p_canvas.drawRightString(x_positions[4] + 70, y_position, str(len(transactions_for_report)))
        y_position -= 15
        p_canvas.drawString(summary_x_start, y_position, "Total Amount (UGX):")
        try: total_amount_str_pdf = f"{float(total_report_amount):,.0f}"
        except: total_amount_str_pdf = "Invalid"
        p_canvas.drawRightString(x_positions[4] + 70, y_position, total_amount_str_pdf)

        p_canvas.save()
        buffer.seek(0)
        download_filename = f"BashMerch_{period}_report_{today.strftime('%Y%m%d')}.pdf"
        return send_file(buffer, mimetype='application/pdf', as_attachment=True, download_name=download_filename)

    except Exception as e:
        print(f"Error generating {period} report: {type(e).__name__} - {e}")
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
    
# app.py -> get_products() route
@app.route('/api/products', methods=['GET'])
@login_required
def get_products():
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        response = ( # Use parentheses for multi-line statement grouping
            supabase.table('products')
            .select('*, category_data:categories(id, name)') # Ensure comment is aligned or on its own line
            .order('name') # This line should align with .select or be indented consistently
            .execute()
        )
        
        products_list = []
        if response.data:
            for p_data in response.data:
                # print(f"--- DEBUG API: Raw p_data from Supabase: {p_data}")
                
                category_info_object = p_data.get('category_data')
                
                # print(f"--- DEBUG API: category_info_object: {category_info_object}")

                products_list.append({
                    'id': p_data['id'],
                    'name': p_data['name'],
                    'sku': p_data.get('sku'),
                    'category_id': category_info_object['id'] if category_info_object else p_data.get('category_id'),
                    'category_name': category_info_object['name'] if category_info_object else 'Uncategorized',
                    'price': p_data['price'],
                    'stock': p_data.get('stock', 0),
                    'status': 'active' if p_data.get('status') else 'inactive', 
                    'description': p_data.get('description'),
                    'image_url': p_data.get('image_url'),
                    'unit_of_measure': p_data.get('unit_of_measure'),
                    'created_at': p_data.get('created_at'),
                    'updated_at': p_data.get('updated_at')
                })
        # print(f"--- DEBUG API: Final products_list: {products_list}")
        return jsonify(products_list)
    except Exception as e:
        print(f"Error fetching products API: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
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
            'unit_of_measure': p_data.get('unit_of_measure'),
            'created_at': response.data['created_at'],
            'updated_at': response.data['updated_at']
        }
        
        return jsonify(product)
    except Exception as e:
        print(f"Error fetching product: {e}")
        return jsonify({"error": "Failed to fetch product"}), 500

# --- API endpoint to create a product (used by products.html JS) ---
@app.route('/api/products', methods=['POST'])
@login_required
def create_product():
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        name = request.form.get('name')
        sku = request.form.get('sku')
        category_id_str = request.form.get('category_id') # Now expecting category_id
        price_str = request.form.get('price')
        stock_str = request.form.get('stock')
        status_form = request.form.get('status', 'inactive')
        description = request.form.get('description', '')

        if not name or not category_id_str or not price_str or not stock_str:
            return jsonify({"error": "Missing required fields (name, category, price, stock)"}), 400
        
        try:
            price = float(price_str)
            stock = int(stock_str)
            category_id = int(category_id_str) if category_id_str else None
            if price < 0 or stock < 0: raise ValueError("Price and stock cannot be negative.")
        except ValueError as ve:
            return jsonify({"error": f"Invalid input format: {ve}"}), 400

        image_url = None
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename): # Make sure allowed_file is defined
                # Using supabase_admin for storage for now (as per previous debug steps)
                if check_supabase_admin() and supabase_admin:
                    try:
                        filename_base = secure_filename(file.filename)
                        filename = f"product_new_{uuid.uuid4()}_{filename_base}"
                        BUCKET_NAME = "product-images"
                        file_bytes = file.read()
                        supabase_admin.storage.from_(BUCKET_NAME).upload(
                            file=file_bytes, path=filename,
                            file_options={"content-type": file.content_type, "cache-control": "3600", "upsert": "false"}
                        )
                        image_url = supabase.storage.from_(BUCKET_NAME).get_public_url(filename)
                    except Exception as upload_error:
                        print(f"Product image upload failed (admin client): {upload_error}")
                        # Decide if creation should fail or proceed without image
                        # For now, let it proceed without image if upload fails
                else:
                    print("Admin client not available for product image upload.")
        
        product_data = {
            'name': name, 'sku': sku, 'category_id': category_id, 'price': price,
            'stock': stock, 'status': (status_form.lower() == 'active'),
            'description': description, 'image_url': image_url,
            'unit_of_measure': unit_of_measure if unit_of_measure else None,
            # created_at and updated_at are usually handled by DB defaults
        }
        
        response = supabase.table('products').insert(product_data).execute()
            
        if response.data and len(response.data) > 0:
            new_product = response.data[0]
            # Fetch category name to return it (frontend might need it)
            cat_name = 'N/A'
            if new_product.get('category_id'):
                cat_res = supabase.table('categories').select('name').eq('id', new_product['category_id']).maybe_single().execute()
                if cat_res.data: cat_name = cat_res.data['name']
            
            new_product_response = {**new_product, 'category_name': cat_name, 'status': 'active' if new_product.get('status') else 'inactive'}
            return jsonify(new_product_response), 201
        else:
            return jsonify({"error": "Failed to create product in database"}), 500

    except Exception as e:
        print(f"Error creating product: {type(e).__name__} - {e}")
        import traceback; traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

# --- API endpoint to update a product (used by products.html JS) ---
@app.route('/api/products/<int:product_id>', methods=['PUT'])
@login_required
def update_product(product_id):
    # Determine which client to use for DB operations.
    # For testing RLS issues, we'll try the admin client.
    # In production, you'd either use admin client for privileged ops
    # or ensure RLS policies are correct for the regular client.
    use_admin_client_for_db = True # SET TO True TO TEST RLS BYPASS

    db_client = None
    if use_admin_client_for_db:
        if check_supabase_admin() and supabase_admin:
            db_client = supabase_admin
            print(f"--- Using Supabase ADMIN client for DB operations on product ID: {product_id} ---")
        else:
            print("CRITICAL: Supabase ADMIN client requested for DB op, but not available.")
            return jsonify({'error': 'System configuration error: Admin client not available.'}), 500
    else:
        if check_supabase():
            db_client = supabase
            print(f"--- Using Supabase REGULAR (anon/auth) client for DB operations on product ID: {product_id} ---")
        else:
            print("CRITICAL: Supabase REGULAR client requested for DB op, but not available (db connection failed).")
            return jsonify({'error': 'Database connection failed'}), 500


    print(f"--- Attempting to update product ID: {product_id} ---")

    try:
        # Fetch current product using the chosen client
        current_product_res = db_client.table('products').select('image_url, category_id').eq('id', product_id).maybe_single().execute()
        if not current_product_res.data:
            print(f"Product ID {product_id} not found for update.")
            return jsonify({"error": "Product not found"}), 404
            
        old_image_url = current_product_res.data.get('image_url')
        print(f"Old image URL for product {product_id}: {old_image_url}")

        update_payload = {}
        if 'name' in request.form: update_payload['name'] = request.form.get('name')
        if 'sku' in request.form: update_payload['sku'] = request.form.get('sku')
        if 'category_id' in request.form:
            cat_id_str = request.form.get('category_id')
            try:
                update_payload['category_id'] = int(cat_id_str) if cat_id_str and cat_id_str.strip() else None
            except ValueError:
                print(f"Invalid category_id format: {cat_id_str}")
                return jsonify({"error": f"Invalid category_id format: {cat_id_str}"}), 400
        if 'price' in request.form:
            try:
                update_payload['price'] = float(request.form.get('price'))
            except ValueError: return jsonify({"error": "Invalid price format."}), 400
        if 'stock' in request.form:
            try:
                update_payload['stock'] = int(request.form.get('stock'))
            except ValueError: return jsonify({"error": "Invalid stock format."}), 400
        if 'status' in request.form: update_payload['status'] = (request.form.get('status', '').lower() == 'active')
        if 'description' in request.form: update_payload['description'] = request.form.get('description')
        
        print(f"Initial update_payload from form (before image processing): {update_payload}")

        new_image_url_for_db = None 

        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename: 
                print(f"Processing uploaded image: {file.filename}, type: {file.content_type}")
                if not allowed_file(file.filename):
                    print(f"File type not allowed for {file.filename}")
                    return jsonify({"error": f"File type {file.filename.rsplit('.',1)[-1]} not allowed."}), 400

                if not (check_supabase_admin() and supabase_admin): # Image uploads should use admin for bucket ops
                    print("Supabase ADMIN client not available for image upload to storage.")
                    return jsonify({"error": "Image upload facility not available."}), 500
                else:
                    BUCKET_NAME = "product-images" # Consider moving to app.config
                    try:
                        bucket_exists = False
                        try:
                            supabase_admin.storage.get_bucket(BUCKET_NAME)
                            print(f"Bucket '{BUCKET_NAME}' found.")
                            bucket_exists = True
                        except Exception as e_get_bucket:
                            if "not found" in str(e_get_bucket).lower() or (hasattr(e_get_bucket, 'status_code') and e_get_bucket.status_code == 400): # Note: 400 for "Bucket not found"
                                print(f"Bucket '{BUCKET_NAME}' not found. Attempting to create.")
                                supabase_admin.storage.create_bucket(
                                    BUCKET_NAME, 
                                    {"public": True, 
                                     "allowed_mime_types": ["image/jpeg", "image/png", "image/gif"], # Align with ALLOWED_EXTENSIONS
                                     "file_size_limit": app.config['MAX_CONTENT_LENGTH']}
                                )
                                print(f"Bucket '{BUCKET_NAME}' created successfully.")
                                bucket_exists = True
                            else:
                                print(f"Error checking/creating bucket '{BUCKET_NAME}': {type(e_get_bucket).__name__} - {e_get_bucket}")
                        
                        if bucket_exists:
                            filename_base = secure_filename(file.filename)
                            filename = f"product_images/{product_id}/{uuid.uuid4()}_{filename_base}" 
                            print(f"Secure filename for storage: {filename}")
                            file_bytes = file.read(); file.seek(0)
                            print(f"Uploading {filename} ({len(file_bytes)} bytes) to bucket {BUCKET_NAME}...")
                            supabase_admin.storage.from_(BUCKET_NAME).upload(
                                file=file_bytes, path=filename,
                                file_options={"content-type": file.content_type, "cache-control": "3600", "upsert": "false"}
                            ) # This should raise an exception on failure
                            
                            # Get public URL (use REGULAR client if bucket is public, or admin client)
                            temp_image_url = supabase.storage.from_(BUCKET_NAME).get_public_url(filename)
                            if temp_image_url and temp_image_url.endswith('?'): # Clean trailing '?'
                                print(f"Warning: Public URL from get_public_url ended with '?'. Stripping it. Original: {temp_image_url}")
                                new_image_url_for_db = temp_image_url[:-1]
                            else:
                                new_image_url_for_db = temp_image_url
                            
                            update_payload['image_url'] = new_image_url_for_db
                            print(f"New image URL set in payload: {new_image_url_for_db}")
                        else:
                            print(f"Cannot upload image: Bucket '{BUCKET_NAME}' not available or creation failed.")
                            return jsonify({"error": "Image storage bucket issue."}), 500
                    except Exception as upload_error:
                        print(f"EXCEPTION during product image upload for {product_id}: {type(upload_error).__name__} - {upload_error}")
                        import traceback; traceback.print_exc()
                        return jsonify({"error": f"Image upload failed: {str(upload_error)}"}), 500
            else: print("Image field was present but no file selected for upload.")
        else: print("No 'image' field in request.files.")

        if not update_payload: 
            print("No changes submitted for product update (no form fields modified, no new image).")
            return jsonify({**(current_product_res.data or {}), 'status': 'active' if (current_product_res.data or {}).get('status') else 'inactive'}), 200

        update_payload['updated_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(f"Final update_payload for DB update: {update_payload}")
        
        db_response_obj = None
        try:
            db_response_obj = db_client.table('products').update(update_payload).eq('id', product_id).execute()
            print(f"Raw DB response object type: {type(db_response_obj)}")
            print(f"Raw DB response dir: {dir(db_response_obj)}")
        except Exception as db_exec_exc:
            print(f"EXCEPTION during DB update execute() call: {type(db_exec_exc).__name__} - {db_exec_exc}")
            import traceback; traceback.print_exc()
            return jsonify({"error": f"Database update execution failed: {str(db_exec_exc)}"}), 500
        
        # More robustly extract attributes
        resp_data = getattr(db_response_obj, 'data', None)
        resp_count = getattr(db_response_obj, 'count', None)
        resp_error = getattr(db_response_obj, 'error', None)
        resp_status = getattr(db_response_obj, 'status_code', None)

        print(f"DB update response - data: {resp_data}, count: {resp_count}, error: {resp_error}, status: {resp_status}")

        if resp_data and len(resp_data) > 0: # Successfully updated and got representation back
            updated_product_data = resp_data[0]
            
            if new_image_url_for_db and old_image_url and old_image_url != new_image_url_for_db:
                if check_supabase_admin() and supabase_admin: # Deletion should use admin
                    try:
                        old_filename_path = old_image_url.split(f"{BUCKET_NAME}/")[-1].split('?')[0]
                        if old_filename_path:
                            print(f"Attempting to delete old image: {old_filename_path}")
                            supabase_admin.storage.from_(BUCKET_NAME).remove([old_filename_path])
                    except Exception as e_del: print(f"Warning: Could not delete old product image {old_image_url}: {e_del}")
            
            cat_name = 'Uncategorized'
            final_category_id = updated_product_data.get('category_id')
            if final_category_id: # Fetch category name using the same client used for DB ops
                cat_res = db_client.table('categories').select('name').eq('id', final_category_id).maybe_single().execute()
                if cat_res.data: cat_name = cat_res.data['name']

            full_updated_product = {**updated_product_data}
            full_updated_product['category_name'] = cat_name
            full_updated_product['status'] = 'active' if full_updated_product.get('status') else 'inactive'
            full_updated_product['unit_of_measure'] = updated_product_data.get('unit_of_measure', (current_product_res.data or {}).get('unit_of_measure'))
            
            print(f"Product {product_id} updated successfully. Returning: {full_updated_product}")
            return jsonify(full_updated_product), 200
        else:
            error_msg_detail = "Failed to update product or no rows affected by the update."
            if resp_error: error_msg_detail += f" DB Error: {resp_error}"
            elif resp_status and resp_status >= 400 : error_msg_detail += f" HTTP Status: {resp_status}"
            print(f"Update for product {product_id} resulted in no data/rows returned. Payload was: {update_payload}. Error: {error_msg_detail}")
            return jsonify({"error": error_msg_detail}), 404 # Or use resp_status if available and >= 400
            
    except Exception as e:
        print(f"CRITICAL ERROR during update_product {product_id}: {type(e).__name__} - {e}")
        import traceback; traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

# app.py

@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    if not (check_supabase_admin() and supabase_admin):
        print(f"--- delete_product({product_id}): Supabase ADMIN client not available.")
        return jsonify({'error': 'System configuration error: Admin client unavailable for delete.'}), 500
    
    db_client = supabase_admin
    print(f"--- delete_product({product_id}): Attempting delete using ADMIN client. ---")

    try:
        # 1. Fetch product details first (optional, but good for getting image_url)
        product_to_delete_response = db_client.table('products') \
            .select('id, image_url, name') \
            .eq('id', product_id) \
            .maybe_single() \
            .execute()

        if not product_to_delete_response.data:
            print(f"--- delete_product({product_id}): Product not found in DB before attempting delete.")
            return jsonify({"error": "Product not found"}), 404
        
        product_name_for_log = product_to_delete_response.data.get('name', 'N/A')
        old_image_url_to_delete = product_to_delete_response.data.get('image_url')
        print(f"--- delete_product({product_id}): Product '{product_name_for_log}' found. Image URL: {old_image_url_to_delete}")

        # 2. Delete the product from the database
        delete_db_response = db_client.table('products') \
            .delete() \
            .eq('id', product_id) \
            .execute()
        
        resp_data = getattr(delete_db_response, 'data', None)
        resp_count = getattr(delete_db_response, 'count', None) 
        resp_error = getattr(delete_db_response, 'error', None)
        resp_status_code = getattr(delete_db_response, 'status_code', None)

        print(f"--- delete_product({product_id}): DB delete response - status_code: {resp_status_code}, data: {resp_data}, count: {resp_count}, error: {resp_error}")

        # Primary check: Was there an explicit error from the Supabase client/PostgREST?
        if resp_error:
            db_error_message = getattr(resp_error, 'message', 'Unknown database error during delete.')
            print(f"--- delete_product({product_id}): Error during DB delete: {db_error_message}")
            return jsonify({"error": f"Failed to delete product from database: {db_error_message}"}), resp_status_code or 500

        # MODIFIED SUCCESS CONDITION:
        # If no error, and data is returned (meaning representation=success), consider it a success.
        # Or, if status_code is explicitly 204 (No Content).
        delete_successful = False
        if resp_data and isinstance(resp_data, list) and len(resp_data) > 0:
            # This is our current case: data is returned!
            print(f"--- delete_product({product_id}): Product delete confirmed by returned data.")
            delete_successful = True
        elif resp_status_code == 204:
            print(f"--- delete_product({product_id}): Product delete confirmed by HTTP status 204 (No Content).")
            delete_successful = True
        
        if not delete_successful:
            # If no explicit error, but also no positive confirmation (no data, status not 204)
            print(f"--- delete_product({product_id}): Product delete from DB not confirmed. Status: {resp_status_code}, Data: {resp_data}. Payload might not have matched any row or other issue.")
            return jsonify({"error": "Product not found or delete operation failed at the database."}), resp_status_code or 404
            
        print(f"--- delete_product({product_id}): Successfully processed delete for product '{product_name_for_log}' from DB logic.")

        # 3. If product had an image, delete it from storage
        if old_image_url_to_delete:
            BUCKET_NAME = "product-images" 
            try:
                url_parts = old_image_url_to_delete.split(f"/{BUCKET_NAME}/")
                if len(url_parts) > 1:
                    old_filename_path = url_parts[-1].split('?')[0] 
                    if old_filename_path:
                        print(f"--- delete_product({product_id}): Attempting to delete image: {old_filename_path} from bucket {BUCKET_NAME} using ADMIN client.")
                        supabase_admin.storage.from_(BUCKET_NAME).remove([old_filename_path])
                        print(f"--- delete_product({product_id}): Storage remove call executed for image: {old_filename_path}")
                    else: print(f"--- delete_product({product_id}): Could not extract valid filename path from URL: {old_image_url_to_delete}")
                else: print(f"--- delete_product({product_id}): Could not parse BUCKET_NAME from image URL: {old_image_url_to_delete}")
            except Exception as e_del_img:
                print(f"--- delete_product({product_id}): WARNING - Could not delete product image {old_image_url_to_delete}. Error: {type(e_del_img).__name__} - {e_del_img}")

        return jsonify({"message": "Product deleted successfully"}), 200

    except Exception as e:
        print(f"--- delete_product({product_id}): UNEXPECTED Error: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Failed to delete product due to an unexpected server error."}), 500   

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
# app.py

@app.route('/products')
@login_required
def products_page():
    if not check_supabase():
        flash("Database connection failed.", "danger")
        return render_template('products.html', categories=[])
    try:
        # Fetch categories from database
        categories_response = supabase.table('categories').select('id, name').order('name').execute()
        return render_template('products.html', categories=categories_response.data or [])
    except Exception as e:
        print(f"Error fetching categories for products page: {type(e).__name__} - {e}")
        flash("Could not load categories for product management.", "danger")
        return render_template('products.html', categories=[])       

@app.route('/api/categories', methods=['GET'])
@login_required
def get_all_categories_api(): # Renamed to avoid conflict if you have other get_all_categories
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500
    try:
        response = supabase.table('categories').select('id, name').order('name').execute()
        if response.data:
            return jsonify(response.data)
        else:
            return jsonify([]) # Return empty list if no categories
    except Exception as e:
        print(f"Error fetching all categories API: {type(e).__name__} - {e}")
        return jsonify({"error": "Failed to fetch categories"}), 500
    
# app.py

# ... (other imports and routes) ...

@app.route('/api/categories', methods=['POST'])
@login_required
def add_category_api():
    if not (check_supabase_admin() and supabase_admin):
        print("CRITICAL: Supabase ADMIN client not available for category POST.")
        return jsonify({'error': 'System configuration error: Admin client not available.'}), 500
    
    db_client = supabase_admin 
    print(f"--- Using Supabase ADMIN client for category POST operation ---")

    try:
        data = request.get_json()
        if not data or 'name' not in data or not data['name'].strip():
            return jsonify({'error': 'Category name is required.'}), 400
        
        category_name = data['name'].strip()
        print(f"Attempting to add/find category: '{category_name}' using admin client.")

        # 1. Check if category already exists (case-insensitive)
        existing_category_response = None
        found_category_data = None
        try:
            print(f"Checking for existing category '{category_name}' using .ilike().limit(1)...")
            existing_category_response = db_client.table('categories') \
                .select('id, name') \
                .ilike('name', category_name) \
                .limit(1) \
                .execute() 
            
            print(f"Response from .ilike().limit(1) check for '{category_name}':")
            print(f"  Type: {type(existing_category_response)}")
            if existing_category_response is not None:
                print(f"  Data: {getattr(existing_category_response, 'data', 'N/A')}") # Should be [] if not found
                if getattr(existing_category_response, 'data', None) and isinstance(existing_category_response.data, list) and len(existing_category_response.data) > 0:
                    found_category_data = existing_category_response.data[0]
                    print(f"  Category found via limit(1): {found_category_data}")
            else: 
                print(f"CRITICAL: Supabase query (limit(1) version) for existing category '{category_name}' returned None object unexpectedly.")
                return jsonify({'error': 'Internal server error during category check (None response object).'}), 500

        except Exception as e_check:
            print(f"EXCEPTION during category existence check (limit(1) version) for '{category_name}': {type(e_check).__name__} - {e_check}")
            import traceback; traceback.print_exc()
            return jsonify({'error': f'Error checking category existence: {str(e_check)}'}), 500

        if hasattr(existing_category_response, 'error') and existing_category_response.error:
            print(f"Error from Supabase while checking category (limit(1) version) '{category_name}': {existing_category_response.error}")
            error_message = getattr(existing_category_response.error, 'message', 'Failed to check category due to a database error.')
            return jsonify({'error': error_message}), getattr(existing_category_response, 'status_code', 500)

        if found_category_data: 
            print(f"Category '{category_name}' already exists with ID: {found_category_data['id']}. Returning existing.")
            return jsonify({'id': found_category_data['id'], 'name': found_category_data['name']}), 200 
        
        # 2. Category does not exist, proceed to insert
        print(f"Category '{category_name}' not found (after limit(1) check). Proceeding to insert.")
        
        insert_response = None
        try:
            insert_payload = {'name': category_name}
            # ***** CORRECTED INSERT *****
            # Remove .select().single() from here. execute() on insert returns the data by default.
            insert_response = db_client.table('categories') \
                .insert(insert_payload) \
                .execute()

            print(f"Response from inserting new category '{category_name}':")
            print(f"  Type: {type(insert_response)}")
            if insert_response is not None:
                print(f"  Data: {getattr(insert_response, 'data', 'N/A')}") # data will be a LIST of inserted records
                print(f"  Error: {getattr(insert_response, 'error', 'N/A')}")
                print(f"  Status Code: {getattr(insert_response, 'status_code', 'N/A')}")
            else: 
                print(f"CRITICAL: Supabase insert category query for '{category_name}' returned None object unexpectedly.")
                return jsonify({'error': 'Internal server error while adding category (None response object).'}), 500

        except Exception as e_insert:
            print(f"EXCEPTION during category insertion for '{category_name}': {type(e_insert).__name__} - {e_insert}")
            import traceback; traceback.print_exc()
            return jsonify({'error': f'Error inserting new category: {str(e_insert)}'}), 500

        if hasattr(insert_response, 'error') and insert_response.error:
            print(f"Error from Supabase while inserting category '{category_name}': {insert_response.error}")
            error_message = getattr(insert_response.error, 'message', 'Failed to create category due to a database error.')
            return jsonify({'error': error_message}), getattr(insert_response, 'status_code', 500)

        # Check insert_response.data, which should be a list containing the inserted record(s)
        if insert_response.data and isinstance(insert_response.data, list) and len(insert_response.data) > 0: 
            new_category = insert_response.data[0] # Get the first (and likely only) inserted record
            print(f"Category '{category_name}' created successfully with ID: {new_category['id']}.")
            # Return only id and name as per client expectation, or the whole new_category object
            return jsonify({'id': new_category.get('id'), 'name': new_category.get('name')}), 201
        else:
            print(f"WARNING: Category insert attempt for '{category_name}' returned no data (or unexpected data structure) and no error from Supabase. Data: {getattr(insert_response, 'data', 'N/A')}")
            return jsonify({'error': 'Failed to create category or retrieve its data after creation.'}), 500

    except Exception as e:
        print(f"Outer EXCEPTION in add_category_api: {type(e).__name__} - {e}")
        import traceback; traceback.print_exc()
        return jsonify({'error': f'An unexpected error occurred: {str(e)}'}), 500
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

