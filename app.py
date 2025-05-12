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

    # Fetch categories for product filtering (for GET request)
    # Fetching all products and customers is done before rendering the form on GET
    # or after a POST error.
    
    if request.method == 'POST':
        try:
            customer_id_form = request.form.get('customer_id')
            payment_method = request.form.get('payment_method')
            notes = request.form.get('notes')
            
            product_ids = request.form.getlist('product_id[]')
            quantities = request.form.getlist('quantity[]')

            # --- Form data to pass back on error ---
            form_data_on_error = {
                'selected_customer_id': customer_id_form,
                'selected_payment_method': payment_method,
                'notes_text': notes,
                'items': [] # We'll reconstruct this if needed
            }
            # This is a bit tricky to pass back dynamic product rows perfectly.
            # For now, we'll just re-fetch all products/customers.

            if not product_ids or not any(pid for pid in product_ids if pid): # Check if any valid product selected
                flash("Please select at least one product.", "danger")
                # Re-fetch data needed for the form
                customers_resp = supabase.table('customers').select('id, name, phone_number').order('name').execute()
                # Fetch active and in-stock products
                products_resp = supabase.table('products').select('id, name, price, stock, category').eq('status', True).gt('stock', 0).order('name').execute()
                categories_resp = supabase.table('products').select('category', count='exact').group('category').execute()
                
                return render_template('add_transaction.html', 
                                     customers=customers_resp.data or [], 
                                     products=products_resp.data or [],
                                     categories=[cat['category'] for cat in categories_resp.data] if categories_resp.data else [],
                                     form_data=form_data_on_error) # Pass back some form data


            transaction_items_to_insert = []
            grand_total = 0
            product_stock_updates = []

            for i, product_id_str in enumerate(product_ids):
                if not product_id_str: continue 

                product_id = int(product_id_str)
                quantity = int(quantities[i])

                if quantity <= 0:
                    flash(f"Quantity for product ID {product_id} must be positive.", "danger")
                    customers_resp = supabase.table('customers').select('id, name, phone_number').order('name').execute()
                    products_resp = supabase.table('products').select('id, name, price, stock, category').eq('status', True).gt('stock', 0).order('name').execute()
                    categories_resp = supabase.table('products').select('category', count='exact').group('category').execute()
                    return render_template('add_transaction.html', customers=customers_resp.data or [], products=products_resp.data or [], categories=[cat['category'] for cat in categories_resp.data] if categories_resp.data else [], form_data=form_data_on_error)

                product_info_res = supabase.table('products').select('price, stock, name').eq('id', product_id).eq('status', True).maybe_single().execute()
                if not product_info_res.data:
                    flash(f"Active product with ID {product_id} not found.", "danger")
                    customers_resp = supabase.table('customers').select('id, name, phone_number').order('name').execute()
                    products_resp = supabase.table('products').select('id, name, price, stock, category').eq('status', True).gt('stock', 0).order('name').execute()
                    categories_resp = supabase.table('products').select('category', count='exact').group('category').execute()
                    return render_template('add_transaction.html', customers=customers_resp.data or [], products=products_resp.data or [], categories=[cat['category'] for cat in categories_resp.data] if categories_resp.data else [], form_data=form_data_on_error)

                product_price = product_info_res.data['price']
                current_stock = product_info_res.data['stock']
                product_name = product_info_res.data['name']

                if quantity > current_stock:
                    flash(f"Not enough stock for '{product_name}'. Available: {current_stock}, Requested: {quantity}.", "danger")
                    customers_resp = supabase.table('customers').select('id, name, phone_number').order('name').execute()
                    products_resp = supabase.table('products').select('id, name, price, stock, category').eq('status', True).gt('stock', 0).order('name').execute()
                    categories_resp = supabase.table('products').select('category', count='exact').group('category').execute()
                    return render_template('add_transaction.html', customers=customers_resp.data or [], products=products_resp.data or [], categories=[cat['category'] for cat in categories_resp.data] if categories_resp.data else [], form_data=form_data_on_error)

                item_total = product_price * quantity
                grand_total += item_total
                
                transaction_items_to_insert.append({
                    'product_id': product_id,
                    'quantity': quantity,
                    'price': product_price 
                })
                product_stock_updates.append({'id': product_id, 'new_stock': current_stock - quantity})

            created_by_db_user_id = get_current_user_db_id_from_session()
            if created_by_db_user_id is None:
                flash("Could not identify processing employee. Please log in again.", "danger")
                customers_resp = supabase.table('customers').select('id, name, phone_number').order('name').execute()
                products_resp = supabase.table('products').select('id, name, price, stock, category').eq('status', True).gt('stock', 0).order('name').execute()
                categories_resp = supabase.table('products').select('category', count='exact').group('category').execute()
                return render_template('add_transaction.html', customers=customers_resp.data or [], products=products_resp.data or [], categories=[cat['category'] for cat in categories_resp.data] if categories_resp.data else [], form_data=form_data_on_error)

            main_transaction_payload = {
                'transaction_code': generate_transaction_code(),
                'date': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                'total_amount': grand_total,
                'customer_id': int(customer_id_form) if customer_id_form else None,
                'payment_method': payment_method,
                'notes': notes,
                'created_by_user_id': created_by_db_user_id
            }
            
            # --- Use a database function (RPC) for atomic transaction processing ---
            # This is the ideal way to handle inserts into multiple tables and stock updates
            # supabase.rpc('create_transaction_with_items_and_update_stock', 
            #              {'transaction_data': main_transaction_payload, 
            #               'items_data': transaction_items_to_insert,
            #               'stock_updates_data': product_stock_updates}).execute()
            # For now, proceeding with separate calls:

            inserted_txn_res = supabase.table('transactions').insert(main_transaction_payload).execute()

            if not inserted_txn_res.data or len(inserted_txn_res.data) == 0:
                flash("Failed to create main transaction record.", "danger")
                customers_resp = supabase.table('customers').select('id, name, phone_number').order('name').execute()
                products_resp = supabase.table('products').select('id, name, price, stock, category').eq('status', True).gt('stock', 0).order('name').execute()
                categories_resp = supabase.table('products').select('category', count='exact').group('category').execute()
                return render_template('add_transaction.html', customers=customers_resp.data or [], products=products_resp.data or [], categories=[cat['category'] for cat in categories_resp.data] if categories_resp.data else [], form_data=form_data_on_error)

            new_transaction_id = inserted_txn_res.data[0]['id']

            for item in transaction_items_to_insert:
                item['transaction_id'] = new_transaction_id
            
            items_insert_res = supabase.table('transaction_items').insert(transaction_items_to_insert).execute()
            if not items_insert_res.data and len(transaction_items_to_insert) > 0:
                flash(f"Transaction #{inserted_txn_res.data[0]['transaction_code']} created, but failed to record items! Please review manually.", "danger")
                # Consider logging this critical failure or attempting rollback logic if possible (complex without DB transaction)

            for stock_update in product_stock_updates:
                stock_update_res = supabase.table('products').update({'stock': stock_update['new_stock']}).eq('id', stock_update['id']).execute()
                if not stock_update_res.data:
                    flash(f"Failed to update stock for product ID {stock_update['id']}. Please check manually.", "warning")


            flash(f"Transaction #{inserted_txn_res.data[0]['transaction_code']} created successfully!", "success")
            return redirect(url_for('transactions'))

        except Exception as e:
            print(f"Error adding transaction: {type(e).__name__} - {e}")
            import traceback
            traceback.print_exc()
            flash("An error occurred while adding the transaction. Please check details and try again.", "danger")
            # Fall through to GET to re-render form with error, re-fetching necessary data

    # GET request or POST failed - show the form
    try:
        customers_resp = supabase.table('customers').select('id, name, phone_number').order('name').execute()
        # Only fetch active products with stock > 0
        products_resp = supabase.table('products').select('id, name, price, stock, category').eq('status', True).gt('stock', 0).order('category').order('name').execute()
        # Fetch distinct categories from active, in-stock products
        # This is a bit inefficient. Better to get categories from products_resp if large.
        # Or, if categories are fixed, define them in Python or a separate table.
        # For now, fetching distinct categories from available products:
        available_categories = sorted(list(set(p['category'] for p in products_resp.data if p['category']))) if products_resp.data else []

    except Exception as e:
        print(f"Error fetching data for add transaction form: {e}")
        flash("Could not load data needed for the transaction form.", "warning")
        customers_resp = {'data': []}
        products_resp = {'data': []}
        available_categories = []

    return render_template('add_transaction.html', 
                         customers=customers_resp.data or [], 
                         products=products_resp.data or [],
                         categories=available_categories,
                         form_data=getattr(request, 'form_data_on_error', {})) # Pass back form data if it was set

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

# app.py
# ... (other imports and setup) ...

@app.route('/api/products', methods=['POST'])
@login_required # Assuming your login_required decorator is defined
def create_product():
    if not check_supabase(): # Checks the regular 'supabase' client
        print("--- create_product: Regular Supabase connection check failed.")
        return jsonify({'error': 'Database connection failed'}), 500

    print(f"--- create_product: Received POST request to /api/products.")
    print(f"--- create_product: Request form data: {request.form}")
    print(f"--- create_product: Request files: {request.files}")

    try:
        name = request.form.get('name')
        sku = request.form.get('sku')
        category = request.form.get('category')
        price_str = request.form.get('price')
        stock_str = request.form.get('stock')
        status_form = request.form.get('status', 'inactive')
        description = request.form.get('description', '')

        print(f"--- create_product: Parsed form fields: name='{name}', sku='{sku}', category='{category}', price='{price_str}', stock='{stock_str}', status='{status_form}'")

        # --- Basic Validation ---
        if not name or not category or not price_str or not stock_str:
            print("--- create_product: VALIDATION FAILED - Missing required fields.")
            return jsonify({"error": "Missing required fields (name, category, price, stock)"}), 400
        
        try:
            price = float(price_str)
            stock = int(stock_str)
            if price < 0 or stock < 0:
                raise ValueError("Price and stock cannot be negative.")
        except ValueError as ve:
            print(f"--- create_product: VALIDATION FAILED - Invalid price or stock: {ve}")
            return jsonify({"error": f"Invalid price or stock format: {ve}"}), 400

        # --- Handle file upload ---
        image_url = None 
        BUCKET_NAME = "product-images" 

        if 'image' in request.files:
            file = request.files['image']
            print(f"--- create_product: 'image' field found in request.files. File object: {file}")
            if file and file.filename: 
                print(f"--- create_product: Processing image file: '{file.filename}', Content-Type: '{file.content_type}'")
                if allowed_file(file.filename): # Make sure allowed_file is defined
                    print(f"--- create_product: File '{file.filename}' is allowed.")
                    filename_base = secure_filename(file.filename)
                    filename = f"{uuid.uuid4()}_{filename_base}" 
                    
                    print(f"--- create_product: Attempting to upload as '{filename}' to existing bucket '{BUCKET_NAME}'.")
                    
                    try:
                        file_bytes = file.read() 
                        print(f"--- create_product: Read {len(file_bytes)} bytes from file for upload.")
                        
                        # --- TEMPORARY DEBUGGING: USE supabase_admin for upload ---
                        print("--- create_product: DEBUGGING - Checking supabase_admin client...")
                        if not check_supabase_admin() or supabase_admin is None: # check_supabase_admin might just print
                            print("--- create_product: Supabase ADMIN client is not initialized or check failed. Cannot proceed with admin upload test.")
                            # For this test, we'll raise an error to make it clear.
                            # In a real scenario, you might fall back or handle differently.
                            raise Exception("Supabase Admin client is not initialized, cannot perform admin storage upload for debugging.")
                        
                        print(f"--- create_product: DEBUGGING - Attempting upload with ADMIN client to {BUCKET_NAME}/{filename}")
                        upload_response_path = supabase_admin.storage.from_(BUCKET_NAME).upload(
                            file=file_bytes,
                            path=filename,
                            file_options={"content-type": file.content_type, "cache-control": "3600", "upsert": "false"}
                        )
                        print(f"--- create_product: DEBUGGING - ADMIN client upload successful. Uploaded path: {upload_response_path}")
                        # --- END OF TEMPORARY DEBUGGING BLOCK ---

                        # If upload was successful, get public URL
                        # (Can use regular 'supabase' client here as bucket is public for reads)
                        image_url = supabase.storage.from_(BUCKET_NAME).get_public_url(filename)
                        print(f"--- create_product: Generated public URL: {image_url}")
                        
                    except Exception as upload_error:
                        print(f"--- create_product: !!!!! ERROR DURING IMAGE UPLOAD (using ADMIN client for debug) !!!!!: {type(upload_error).__name__} - {upload_error}")
                        import traceback
                        traceback.print_exc()
                        # image_url remains None
                else:
                    print(f"--- create_product: File type not allowed for '{file.filename}'. Allowed: {app.config['ALLOWED_EXTENSIONS']}")
            else:
                print(f"--- create_product: No file selected in 'image' input or filename is empty.")
        else:
            print(f"--- create_product: 'image' field NOT found in request.files.")

        # --- Prepare product data for DB ---
        status_bool = status_form.lower() == 'active'
        product_data_for_db = {
            'name': name, 'sku': sku if sku else None, 'category': category, 'price': price,
            'stock': stock, 'status': status_bool, 'description': description, 'image_url': image_url 
        }
        print(f"--- create_product: Final product data for DB insert: {product_data_for_db}")

        # --- Insert into database ---
        try:
            db_response = supabase.table('products').insert(product_data_for_db).execute()
            
            if db_response.data and len(db_response.data) > 0:
                new_product = db_response.data[0]
                new_product_response = {
                    'id': new_product['id'], 'name': new_product['name'], 'sku': new_product.get('sku'),
                    'category': new_product['category'], 'price': new_product['price'], 'stock': new_product['stock'],
                    'status': 'active' if new_product.get('status', False) else 'inactive',
                    'description': new_product.get('description'), 'image_url': new_product.get('image_url'),
                    'created_at': new_product.get('created_at'), 'updated_at': new_product.get('updated_at')
                }
                print(f"--- create_product: Product created successfully in DB. ID: {new_product_response['id']}")
                return jsonify(new_product_response), 201
            else:
                print(f"--- create_product: DB insert executed, but no data returned or data is empty. Status: {db_response.status_code}, Full Resp: {db_response}")
                return jsonify({"error": "Failed to create product: No data returned from database after insert."}), 500
        except Exception as db_error:
            print(f"--- create_product: FAILED to create product in DB (Exception). Type: {type(db_error).__name__}, Error: {db_error}")
            import traceback
            traceback.print_exc()
            error_message = str(db_error)
            if hasattr(db_error, 'message') and db_error.message: error_message = db_error.message
            elif hasattr(db_error, 'details') and db_error.details: error_message = db_error.details 
            elif hasattr(db_error, 'args') and db_error.args:
                try:
                    err_dict = eval(str(db_error.args[0]))
                    if isinstance(err_dict, dict) and 'message' in err_dict: error_message = err_dict['message']
                except: pass
            return jsonify({"error": f"Database error: {error_message}"}), 500

    except Exception as e:
        print(f"--- create_product: !!!!! UNEXPECTED GLOBAL ERROR in create_product endpoint !!!!!: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/api/products/<int:product_id>', methods=['PUT'])
@login_required
def update_product(product_id):
    # This is the outermost try for the entire function
    try:
        if not check_supabase(): # For initial DB connection checks if any
            print(f"--- update_product({product_id}): Regular Supabase connection check failed.")
            return jsonify({'error': 'Database connection failed'}), 500

        print(f"--- update_product({product_id}): Received PUT request.")
        print(f"--- update_product({product_id}): Request form data: {request.form}")
        print(f"--- update_product({product_id}): Request files: {request.files}")

        # --- Fetch existing product data first ---
        try:
            existing_product_response = supabase.table('products').select('id, image_url').eq('id', product_id).maybe_single().execute()
            if not existing_product_response.data:
                print(f"--- update_product({product_id}): Product not found in DB for initial fetch.")
                return jsonify({"error": "Product not found"}), 404
            current_product_data = existing_product_response.data
            old_image_url = current_product_data.get('image_url')
            print(f"--- update_product({product_id}): Found existing product. Old image_url: {old_image_url}")
        except Exception as fetch_err:
            print(f"--- update_product({product_id}): Error fetching existing product: {type(fetch_err).__name__} - {fetch_err}")
            import traceback
            traceback.print_exc()
            return jsonify({"error": "Failed to retrieve existing product data"}), 500

        # --- Retrieve form data for update ---
        name = request.form.get('name')
        sku = request.form.get('sku')
        category = request.form.get('category')
        price_str = request.form.get('price')
        stock_str = request.form.get('stock')
        status_form = request.form.get('status')
        description = request.form.get('description')

        print(f"--- update_product({product_id}): Parsed form fields: name='{name}', sku='{sku}', category='{category}', price='{price_str}', stock='{stock_str}', status='{status_form}'")

        update_payload = {}
        if name is not None: update_payload['name'] = name
        if sku is not None: update_payload['sku'] = sku if sku else None
        if category is not None: update_payload['category'] = category
        if price_str is not None:
            try: update_payload['price'] = float(price_str)
            except ValueError: return jsonify({"error": "Invalid price format"}), 400
        if stock_str is not None:
            try: update_payload['stock'] = int(stock_str)
            except ValueError: return jsonify({"error": "Invalid stock format"}), 400
        if status_form is not None: update_payload['status'] = (status_form.lower() == 'active')
        if description is not None: update_payload['description'] = description
        
        new_image_url = None
        BUCKET_NAME = "product-images"

        if 'image' in request.files:
            file = request.files['image']
            print(f"--- update_product({product_id}): 'image' field found. File: {file}")
            if file and file.filename:
                print(f"--- update_product({product_id}): Processing new image: '{file.filename}'")
                if allowed_file(file.filename): 
                    print(f"--- update_product({product_id}): New file allowed.")
                    filename_base = secure_filename(file.filename)
                    filename = f"{uuid.uuid4()}_{filename_base}"
                    print(f"--- update_product({product_id}): Uploading new image as '{filename}'")
                    
                    try:
                        file_bytes = file.read()
                        print(f"--- update_product({product_id}): Read {len(file_bytes)} bytes from new file.")
                        
                        print(f"--- update_product({product_id}): DEBUGGING - Checking supabase_admin for storage upload...")
                        if not check_supabase_admin() or supabase_admin is None:
                            print(f"--- update_product({product_id}): ADMIN client not initialized for storage upload.")
                            raise Exception("Admin client not initialized for storage operation.")
                        
                        print(f"--- update_product({product_id}): DEBUGGING - Uploading image with ADMIN client...")
                        upload_response_path = supabase_admin.storage.from_(BUCKET_NAME).upload(
                            file=file_bytes, path=filename,
                            file_options={"content-type": file.content_type, "cache-control": "3600", "upsert": "false"}
                        )
                        print(f"--- update_product({product_id}): DEBUGGING - ADMIN client image upload path: {upload_response_path}")

                        new_image_url = supabase.storage.from_(BUCKET_NAME).get_public_url(filename) 
                        update_payload['image_url'] = new_image_url
                        print(f"--- update_product({product_id}): New image URL: {new_image_url}")
                        
                    except Exception as upload_error:
                        print(f"--- update_product({product_id}): ERROR DURING NEW IMAGE UPLOAD: {type(upload_error).__name__} - {upload_error}")
                        import traceback
                        traceback.print_exc()
                        return jsonify({"error": f"Failed to upload new image: {str(upload_error)}"}), 500
                else: 
                    print(f"--- update_product({product_id}): New file type not allowed.")
                    return jsonify({"error": "New image file type not allowed"}), 400
            else: 
               print(f"--- update_product({product_id}): Image field present but no file selected or empty filename.")
        else: 
           print(f"--- update_product({product_id}): No new image file in request. Retaining old image if any.")


        if not update_payload: 
            print(f"--- update_product({product_id}): No textual fields to update.")
            if new_image_url is None: 
                print(f"--- update_product({product_id}): No changes detected at all (no text fields, no new image).")
                final_product_data_resp = supabase.table('products').select('*').eq('id', product_id).maybe_single().execute()
                if final_product_data_resp.data:
                    resp_data = final_product_data_resp.data
                    resp_data['status'] = 'active' if resp_data.get('status', False) else 'inactive'
                    return jsonify(resp_data), 200
                else: 
                    return jsonify({"message": "No changes made; product may no longer exist."}), 404 
            

        update_payload['updated_at'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        print(f"--- update_product({product_id}): Final DB update payload: {update_payload}")

        # --- Database Update Section (TEMPORARILY USING supabase_admin) ---
        try:
            print(f"--- update_product({product_id}): DEBUGGING - Checking supabase_admin for DB update...")
            if not check_supabase_admin() or supabase_admin is None:
                print(f"--- update_product({product_id}): Supabase ADMIN client is not initialized. Cannot proceed with admin DB update test.")
                raise Exception("Supabase Admin client is not initialized for DB update debugging.")

            print(f"--- update_product({product_id}): DEBUGGING - Attempting DB update with ADMIN client...")
            # REMOVED returning="representation" from here:
            db_response = supabase_admin.table('products').update(update_payload).eq('id', product_id).execute() 
            
            print(f"--- update_product({product_id}): DEBUGGING - ADMIN client DB update response: data={db_response.data}, count={getattr(db_response, 'count', 'N/A')}")

            if db_response.data and len(db_response.data) > 0:
                updated_product_from_db = db_response.data[0] 
                print(f"--- update_product({product_id}): Product updated successfully in DB (using ADMIN client). Data: {updated_product_from_db}")

                if new_image_url and old_image_url and old_image_url != new_image_url:
                    try:
                        old_filename_with_query = old_image_url.split(f"{BUCKET_NAME}/")[-1]
                        old_filename = old_filename_with_query.split('?')[0]
                        if old_filename:
                            print(f"--- update_product({product_id}): Deleting old image: {old_filename} using ADMIN client.")
                            supabase_admin.storage.from_(BUCKET_NAME).remove([old_filename])
                            print(f"--- update_product({product_id}): Successfully deleted old image.")
                    except Exception as e_del: 
                        print(f"--- update_product({product_id}): WARNING - Could not delete old image: {e_del}")
                
                # By default, supabase-py update().execute() returns the updated rows in .data
                final_response_product = updated_product_from_db 
                final_response_product['status'] = 'active' if final_response_product.get('status', False) else 'inactive'
                return jsonify(final_response_product), 200
            
            elif not db_response.data or len(db_response.data) == 0:
                print(f"--- update_product({product_id}): ADMIN client DB update executed, but no data returned (0 rows affected). Product ID {product_id} likely not found. Resp: {db_response}")
                return jsonify({"error": f"Failed to update product {product_id} (using ADMIN client): Product ID not found or no changes made."}), 404
            
        except Exception as db_error: 
            print(f"--- update_product({product_id}): FAILED to update product in DB (Exception, using ADMIN client). Type: {type(db_error).__name__}, Error: {db_error}")
            import traceback
            traceback.print_exc()
            error_message = str(db_error)
            if hasattr(db_error, 'message') and db_error.message: error_message = db_error.message
            elif hasattr(db_error, 'details') and db_error.details: error_message = db_error.details
            return jsonify({"error": f"Database error during update (admin debug): {error_message}"}), 500

    # This is the except for the outermost try block of the entire function
    except Exception as e:
        print(f"--- update_product({product_id}): !!!!! UNEXPECTED GLOBAL ERROR !!!!!: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"An unexpected error occurred: {str(e)}"}), 500

# The next route definition should start here, correctly unindented
@app.route('/api/products/<int:product_id>', methods=['DELETE'])
@login_required
def delete_product(product_id):
    # ... implementation of delete_product ...
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500
    # ... rest of your delete logic
    try:
        # First check if product exists
        check_response = supabase.table('products') \
            .select('id, image_url') \
            .eq('id', product_id) \
            .maybe_single() \
            .execute()
            
        if not check_response.data:
            return jsonify({"error": "Product not found"}), 404
        
        product_to_delete = check_response.data
        old_image_url_to_delete = product_to_delete.get('image_url')

        # Delete the product from the database
        delete_db_response = supabase.table('products') \
            .delete() \
            .eq('id', product_id) \
            .execute()
        
        # supabase-py v1+ delete().execute() typically returns data (list of deleted items) if successful
        # and raises an exception on API error.
        if not delete_db_response.data or len(delete_db_response.data) == 0:
            # This might happen if the ID didn't match or RLS prevented deletion without an error
            print(f"--- delete_product({product_id}): Product not found for deletion or no data returned from DB delete. Response: {delete_db_response}")
            return jsonify({"error": "Product not found or delete not confirmed by database"}), 404
            
        print(f"--- delete_product({product_id}): Successfully deleted product from DB.")

        # If product had an image, delete it from storage
        if old_image_url_to_delete:
            BUCKET_NAME = "product-images"
            try:
                old_filename_with_query = old_image_url_to_delete.split(f"{BUCKET_NAME}/")[-1]
                old_filename = old_filename_with_query.split('?')[0]
                if old_filename:
                    print(f"--- delete_product({product_id}): Attempting to delete image: {old_filename} from bucket {BUCKET_NAME} using ADMIN client.")
                    if not check_supabase_admin() or supabase_admin is None:
                        print(f"--- delete_product({product_id}): Supabase ADMIN client not available for deleting image.")
                    else:
                        supabase_admin.storage.from_(BUCKET_NAME).remove([old_filename])
                        print(f"--- delete_product({product_id}): Successfully deleted image: {old_filename}")
            except Exception as e_del_img:
                print(f"--- delete_product({product_id}): WARNING - Could not delete product image {old_image_url_to_delete}: {e_del_img}")

        return jsonify({"message": "Product deleted successfully"}), 200
    except Exception as e:
        print(f"--- delete_product({product_id}): Error deleting product: {type(e).__name__} - {e}")
        import traceback
        traceback.print_exc()
        error_message = str(e)
        if hasattr(e, 'message') and e.message: error_message = e.message
        elif hasattr(e, 'details') and e.details: error_message = e.details
        return jsonify({"error": f"Failed to delete product: {error_message}"}), 500       

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

