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
from flask import request, get_flashed_messages

# Load environment variables
load_dotenv('.env')

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY')

# Initialize Supabase client with options
supabase_url = os.getenv('SUPABASE_URL')
supabase_key = os.getenv('SUPABASE_KEY')

# --- Supabase Client Initialization ---
# Check if URL and Key are loaded
if not supabase_url or not supabase_key:
    print("Error: SUPABASE_URL or SUPABASE_KEY not found in environment variables.")
    # Handle this error appropriately, maybe exit or raise an exception
    # For now, we'll create a placeholder client to avoid NameError later
    supabase = None
else:
    try:
        supabase: Client = create_client(
            supabase_url,
            supabase_key,
            options=ClientOptions(
                postgrest_client_timeout=30, # Increased timeout slightly
                schema="public"
            )
        )
        print("Supabase client initialized successfully.")
    except Exception as e:
        print(f"Error initializing Supabase client: {e}")
        supabase = None # Set to None if initialization fails

# Helper function to check Supabase connection
def check_supabase():
    if supabase is None:
        flash("Application error: Database connection failed. Please contact support.", "danger")
        return False
    return True

@app.context_processor
def inject_globals():
    user_info = session.get('user', None)
    def format_ugx(value):
        try:
            amount = float(value)
            return f"UGX {amount:,.0f}"
        except (ValueError, TypeError):
            return "UGX 0"
    # ADD 'now': datetime.datetime.utcnow here (or .now if timezone doesn't matter)
    return dict(user=user_info, format_ugx=format_ugx, now=datetime.datetime.utcnow)

@app.route('/login', methods=['GET', 'POST'])
def login():
    # Check if Supabase client is initialized
    if not check_supabase():
        return render_template('login.html', error='System configuration error.')

    # If user is already logged in, redirect to dashboard
    if 'access_token' in session and 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Basic validation
        if not email or not password:
            flash('Email and password are required.', 'warning')
            return render_template('login.html')

        try:
            # Sign in with Supabase Auth
            auth_response = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })

            user = auth_response.user
            session['access_token'] = auth_response.session.access_token
            session['refresh_token'] = auth_response.session.refresh_token
            session['user'] = {
                'id': user.id,
                'email': user.email,
                'role': user.user_metadata.get('role', 'user') if user.user_metadata else 'user'
            }

            print(f"Login successful for {email}")
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))

        except Exception as e:
            # Extract a cleaner error message if possible
            error_message = str(e)
            if "Invalid login credentials" in error_message:
                flash('Invalid email or password.', 'danger')
            else:
                flash('An error occurred during login. Please try again.', 'danger')
                print(f"Login error for {email}: {error_message}") # Log the full error
            return render_template('login.html')

    return render_template('login.html')


# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session or 'user' not in session:
            flash('Please log in to access this page.', 'info')
            return redirect(url_for('login', next=request.url))
        # Optional: Add session refresh logic here if needed frequently
        # try:
        #     refresh_session()
        # except Exception as e:
        #     print(f"Session refresh failed during request: {str(e)}")
        #     session.clear()
        #     flash('Your session has expired. Please log in again.', 'warning')
        #     return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
@login_required
def index():
    # Root should always go to dashboard if logged in
    return redirect(url_for('dashboard'))

# Helper function to format time differences nicely
def time_ago(dt_string):
    if not dt_string:
        return "N/A"
    try:
        then = datetime.datetime.fromisoformat(dt_string.replace('Z', '+00:00')) # Handle timezone
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = relativedelta(now, then)

        if delta.years > 0:
            return f"{delta.years} year{'s' if delta.years > 1 else ''} ago"
        if delta.months > 0:
            return f"{delta.months} month{'s' if delta.months > 1 else ''} ago"
        if delta.days > 0:
            return f"{delta.days} day{'s' if delta.days > 1 else ''} ago"
        if delta.hours > 0:
            return f"{delta.hours} hour{'s' if delta.hours > 1 else ''} ago"
        if delta.minutes > 0:
            return f"{delta.minutes} minute{'s' if delta.minutes > 1 else ''} ago"
        return "Just now"
    except Exception as e:
        print(f"Error formatting time_ago for '{dt_string}': {e}")
        return "Invalid date"


@app.route('/dashboard')
@login_required
def dashboard():
    if not check_supabase():
        return render_template('dashboard.html', error='Database connection failed.')

    # Refresh the session if needed (optional, can be done per request)
    # try:
    #     refresh_session()
    # except Exception as e:
    #     print(f"Session refresh error on dashboard load: {str(e)}")
    #     session.clear()
    #     flash('Session expired. Please log in again.', 'warning')
    #     return redirect(url_for('login'))

    try:
        # Get today's date range (start and end of day)
        today_start = datetime.datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        today_end = today_start + datetime.timedelta(days=1)

        # --- Fetch Dashboard Data ---
        # Total sales for today
        sales_response = supabase.table('transactions') \
            .select('total_amount') \
            .gte('date', today_start.isoformat()) \
            .lt('date', today_end.isoformat()) \
            .execute()
        total_sales = sum(txn['total_amount'] for txn in sales_response.data) if sales_response.data else 0

        # Transaction count for today
        txn_count_response = supabase.table('transactions') \
            .select('id', count='exact') \
            .gte('date', today_start.isoformat()) \
            .lt('date', today_end.isoformat()) \
            .execute()
        total_transactions = txn_count_response.count if hasattr(txn_count_response, 'count') else 0

        # Get top products (assuming RPC exists and works)
        # Make sure the RPC handles the date correctly
        top_products_response = supabase.rpc('get_top_products', {'query_date': today_start.date().isoformat()}).execute()
        top_products = [{'name': p['name'], 'units': p['units']} for p in top_products_response.data] if top_products_response.data else []

        # Get inventory alerts (Low stock: 1-5, Out of stock: 0)
        # Use count='exact' for efficiency
        low_stock_response = supabase.table('products').select('id', count='exact').gt('stock_quantity', 0).lte('stock_quantity', 5).execute()
        low_stock_count = low_stock_response.count if hasattr(low_stock_response, 'count') else 0

        out_of_stock_response = supabase.table('products').select('id', count='exact').eq('stock_quantity', 0).execute()
        out_of_stock_count = out_of_stock_response.count if hasattr(out_of_stock_response, 'count') else 0

        # Get recent customers (assuming RPC exists)
        recent_customers_response = supabase.rpc('get_recent_customers').execute()
        recent_customers = []
        if recent_customers_response.data:
            for customer in recent_customers_response.data:
                recent_customers.append({
                    'name': customer.get('name', 'Unknown'), # Use .get for safety
                    'time_ago': time_ago(customer.get('latest_transaction'))
                })

        # Get recent transactions
        recent_transactions_response = supabase.table('transactions') \
            .select('id, transaction_code, date, total_amount, customers(name)') \
            .order('date', desc=True) \
            .limit(5) \
            .execute() # Limit to fewer transactions for dashboard performance
        recent_transactions = []
        if recent_transactions_response.data:
            for txn in recent_transactions_response.data:
                # You might not need product details on the dashboard overview
                # products_response = supabase.table('transaction_items').select('products(name)').eq('transaction_id', txn['id']).execute()
                # products_str = ", ".join([p['products']['name'] for p in products_response.data]) if products_response.data else ""

                recent_transactions.append({
                    'id': txn['transaction_code'], # Use transaction_code if it's the display ID
                    'date': datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%Y %I:%M %p'),
                    'customer_name': txn['customers']['name'] if txn['customers'] else 'N/A',
                    # 'products': products_str, # Optional
                    'total': txn['total_amount'] # Pass the number, format in template
                })

        # --- Render Template ---
        return render_template(
            'dashboard.html',
            total_sales=total_sales, # Pass number, format in template
            total_transactions=total_transactions,
            top_products=top_products,
            low_stock_count=low_stock_count,
            out_of_stock_count=out_of_stock_count,
            recent_customers=recent_customers,
            recent_transactions=recent_transactions
            # user is injected globally by context processor
        )

    except Exception as e:
        print(f"Dashboard error: {str(e)}")
        flash(f"Error loading dashboard data: {str(e)}", "danger")
        # Show a fallback dashboard page
        return render_template(
            'dashboard.html',
            total_sales=0,
            total_transactions=0,
            top_products=[],
            low_stock_count=0,
            out_of_stock_count=0,
            recent_customers=[],
            recent_transactions=[],
            error="Could not load all dashboard data."
        )

@app.route('/register', methods=['GET', 'POST'])
def register():
    if not check_supabase():
        return render_template('login.html', reg_error='System configuration error.') # Render on login page

    # Redirect logged-in users away from register page
    if 'access_token' in session and 'user' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        # Add other fields like name if needed
        # first_name = request.form.get('first_name')
        # last_name = request.form.get('last_name')

        # --- Validation ---
        error = None
        if not email or not password or not confirm_password:
            error = "All fields are required."
        elif not re.match(r"^\S+@\S+\.\S+$", email): # Simple email regex
             error = "Invalid email format."
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != confirm_password:
            error = "Passwords do not match."
        # Add name validation if needed
        # elif not first_name or not last_name:
        #     error = "First and last name are required."

        if error:
            flash(error, 'danger')
            # Return form values to refill the form, except passwords
            return render_template('login.html', reg_email=email) # Render on login page

        try:
            # --- Register user with Supabase Auth ---
            # Include metadata like role or name during signup
            auth_response = supabase.auth.sign_up({
                "email": email,
                "password": password,
                "options": {
                    "data": {
                        "role": "user", # Default role
                        # "first_name": first_name,
                        # "last_name": last_name
                    }
                }
            })

            # Check if user object exists in response
            if auth_response.user:
                 print(f"Registration submitted for {email}. User ID: {auth_response.user.id}")
                 flash("Registration successful! Please check your email to confirm your account.", 'success')
                 return redirect(url_for('login')) # Redirect to login after registration
            else:
                 # This case might indicate email confirmation is off or an unexpected response
                 print(f"Registration response for {email} did not contain user object.")
                 flash("Registration submitted. Please check your email.", 'info')
                 return redirect(url_for('login'))


        except Exception as e:
            error_message = str(e)
            print(f"Registration error: {error_message}")
            if 'User already registered' in error_message:
                flash("This email address is already registered.", 'warning')
            else:
                flash(f"Registration failed. Please try again.", 'danger')
            # Return form values
            return render_template('login.html', reg_email=email) # Render on login page

    # For GET request, just show the registration part of the login page
    # You might need JS on login.html to show the correct form
    return render_template('login.html')

@app.route('/logout')
def logout():
    print("\n--- Logout Route ---") # Added newline for clarity
    if not check_supabase():
         session.clear() # Clear session even if Supabase fails
         flash("Logged out.", 'info')
         print("Supabase check failed, session cleared, redirecting to login.")
         return redirect(url_for('login'))

    access_token = session.get('access_token')
    user_email = session.get('user',{}).get('email','UNKNOWN_USER') # Get email for logging
    if access_token:
        try:
            # Use the stored access token to sign out
            supabase.auth.sign_out() # Pass the access token if required by your Supabase client version/config
            print(f"Supabase sign out successful for {user_email}.")
        except Exception as e:
            print(f"Error during Supabase sign out for {user_email}: {str(e)}")
            # Log the error, but proceed with clearing the session

    session.clear()
    flash("You have been successfully logged out.", 'success')
    # Peek at session right after flash and clear
    print(f"Flashed logout message. Session cleared. Session content now: {dict(session)}")
    return redirect(url_for('login'))



# Helper function to refresh the session token (use cautiously)
def refresh_session():
    if 'refresh_token' in session and supabase: # Check if supabase client exists
        try:
            # print("Attempting to refresh session...") # Debugging
            auth_response = supabase.auth.refresh_session(session['refresh_token'])
            if auth_response.session:
                session['access_token'] = auth_response.session.access_token
                session['refresh_token'] = auth_response.session.refresh_token
                # Optionally update user info if it can change
                # session['user'] = { ... updated info ... }
                # print("Session refreshed successfully.") # Debugging
            else:
                 # This case might happen if refresh token is invalid
                 raise Exception("Refresh token invalid or expired")

        except Exception as e:
            print(f"Token refresh error: {str(e)}")
            session.clear() # Clear session if refresh fails
            raise e # Re-raise exception to be caught by caller

# =========================================
# Main Application Page Routes
# =========================================

@app.route('/products')
@login_required
def products():
    if not check_supabase(): return redirect(url_for('dashboard')) # Redirect if DB fails

    try:
        # Add logic to fetch products from Supabase
        response = supabase.table('products').select('*').order('name').execute()
        products_data = response.data if response.data else []
        return render_template('products.html', products=products_data)
    except Exception as e:
        print(f"Error fetching products: {e}")
        flash("Could not load product data.", "danger")
        return render_template('products.html', products=[]) # Render page with empty list


@app.route('/transactions')
@login_required
def transactions():
    if not check_supabase(): return redirect(url_for('dashboard'))

    try:
         # Add logic to fetch transactions from Supabase
        response = supabase.table('transactions') \
            .select('*, customers(name)') \
            .order('date', desc=True) \
            .execute()
        transactions_data = []
        if response.data:
            for txn in response.data:
                 transactions_data.append({
                    'id': txn['transaction_code'],
                    'date': datetime.datetime.fromisoformat(txn['date'].replace('Z', '+00:00')).strftime('%d/%m/%Y %I:%M %p'),
                    'customer_name': txn['customers']['name'] if txn['customers'] else 'N/A',
                    'total': txn['total_amount'] # Pass number
                })
        return render_template('transactions.html', transactions=transactions_data)
    except Exception as e:
        print(f"Error fetching transactions: {e}")
        flash("Could not load transaction data.", "danger")
        return render_template('transactions.html', transactions=[])


@app.route('/customers')
@login_required
def customers():
    if not check_supabase(): return redirect(url_for('dashboard'))

    try:
        # Add logic to fetch customers from Supabase
        response = supabase.table('customers').select('*').order('name').execute()
        customers_data = response.data if response.data else []
        return render_template('customers.html', customers=customers_data)
    except Exception as e:
        print(f"Error fetching customers: {e}")
        flash("Could not load customer data.", "danger")
        return render_template('customers.html', customers=[])


@app.route('/reports')
@login_required
def reports():
    # This page might just show options to generate reports
    # Actual report generation could be via API calls or form submissions
    return render_template('reports.html')


@app.route('/users')
@login_required
def users():
    # --- CORRECTED ROUTE ---
    if not check_supabase(): return redirect(url_for('dashboard'))

    # Add Authorization Check (Example: only Admins can see users)
    user_role = session.get('user', {}).get('role')
    if user_role != 'admin': # Adjust 'admin' role name if different
        flash("You do not have permission to view this page.", "warning")
        return redirect(url_for('dashboard'))

    try:
        # Fetch users (typically from auth.users, might need admin privileges)
        # NOTE: Accessing auth.users directly might require service role key or specific permissions
        # Placeholder: This example assumes you have a 'profiles' table linked to auth.users
        # or you handle user display differently.

        # Example using hypothetical 'profiles' table linked by user_id:
        # response = supabase.table('profiles').select('user_id, first_name, last_name, email, role, created_at, status').execute()
        # users_data = response.data if response.data else []

        # --- Placeholder Data ---
        # Replace this with your actual Supabase query to get users
        # You might need to query Supabase Auth users list (requires admin API usually)
        # or a separate 'profiles' table linked to auth users.
        users_data = [
             {'user_id': 'USR-001', 'name': 'Admin User', 'email': 'admin@example.com', 'role': 'Administrator', 'status': 'Active', 'date_added': '2024-01-15'},
             {'user_id': 'USR-002', 'name': 'Manager User', 'email': 'manager@example.com', 'role': 'Manager', 'status': 'Active', 'date_added': '2024-02-20'},
             {'user_id': 'USR-003', 'name': 'Staff User', 'email': 'staff@example.com', 'role': 'Staff', 'status': 'Inactive', 'date_added': '2024-03-10'},
        ]
        # --- End Placeholder ---

        return render_template('users.html', users=users_data)
    except Exception as e:
        print(f"Error fetching users: {e}")
        flash("Could not load user data.", "danger")
        return render_template('users.html', users=[])


# =========================================
# API Routes (Example: Report Generation)
# =========================================

@app.route('/api/reports/<period>', methods=['GET'])
@login_required
def generate_report_api(period): # Renamed function to avoid conflict
    if not check_supabase():
        return jsonify({'error': 'Database connection failed'}), 500

    today = datetime.datetime.now().date()
    end_date = today # Default end date

    if period == 'daily':
        start_date = today
        title = f"Daily Report - {today.strftime('%d %b %Y')}"
    elif period == 'weekly':
        start_date = today - datetime.timedelta(days=today.weekday())
        title = f"Weekly Report ({start_date.strftime('%d %b')} - {end_date.strftime('%d %b %Y')})"
    elif period == 'monthly':
        start_date = today.replace(day=1)
        title = f"Monthly Report - {start_date.strftime('%B %Y')}"
    else:
        return jsonify({'error': 'Invalid report period specified'}), 400

    # Convert to datetime for Supabase filtering if needed
    start_datetime = datetime.datetime.combine(start_date, datetime.time.min)
    end_datetime = datetime.datetime.combine(end_date, datetime.time.max)

    try:
        # Query transactions within the period
        transactions_response = supabase.table('transactions') \
            .select('date, transaction_code, total_amount, customers(name)') \
            .gte('date', start_datetime.isoformat()) \
            .lte('date', end_datetime.isoformat()) \
            .order('date') \
            .execute()

        transactions = transactions_response.data if transactions_response.data else []

        # --- Create PDF report ---
        buffer = io.BytesIO()
        p = canvas.Canvas(buffer, pagesize=letter)
        width, height = letter # Get page dimensions

        # --- PDF Styling ---
        p.setFont('Helvetica-Bold', 16)
        p.drawString(50, height - 50, "Bash Merchandise Management") # Title
        p.setFont('Helvetica', 14)
        p.drawString(50, height - 70, title) # Report Period

        p.setFont('Helvetica', 10)
        p.line(50, height - 80, width - 50, height - 80) # Separator line

        # Table Header
        y_position = height - 100
        x_positions = [50, 150, 300, 400, 500] # Adjust spacing as needed
        headers = ["Date", "Transaction ID", "Customer", "Amount (UGX)"]
        p.setFont('Helvetica-Bold', 10)
        for i, header in enumerate(headers):
             p.drawString(x_positions[i], y_position, header)

        y_position -= 15 # Space after header
        p.setFont('Helvetica', 9)

        # Table Rows
        total_report_amount = 0
        for txn in transactions:
            if y_position < 60: # Check if space remaining, add new page if not
                p.showPage()
                p.setFont('Helvetica-Bold', 10) # Redraw header on new page
                y_position = height - 100
                for i, header in enumerate(headers):
                     p.drawString(x_positions[i], y_position, header)
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
            p.drawRightString(x_positions[3] + 100, y_position, f"{amount:,.0f}") # Right align amount

            y_position -= 15 # Move down for next row

        # Report Summary
        p.line(50, y_position + 5, width - 50, y_position + 5)
        y_position -= 10
        p.setFont('Helvetica-Bold', 10)
        p.drawString(x_positions[2], y_position, "Total Transactions:")
        p.drawString(x_positions[3], y_position, str(len(transactions)))
        y_position -= 15
        p.drawString(x_positions[2], y_position, "Total Amount:")
        p.drawRightString(x_positions[3] + 100, y_position, f"{total_report_amount:,.0f}")

        # Save PDF
        p.save()
        buffer.seek(0)

        # --- Send PDF File ---
        download_filename = f"BashMerch_{period}_report_{today.strftime('%Y%m%d')}.pdf"
        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=download_filename
        )

    except Exception as e:
        print(f"Error generating {period} report: {e}")
        return jsonify({'error': f'Failed to generate report: {str(e)}'}), 500


# =========================================
# Run the Application
# =========================================
if __name__ == '__main__':
    # Check for Supabase client again before running
    if supabase is None:
        print("\nCRITICAL ERROR: Supabase client failed to initialize. Cannot start Flask app.")
        print("Please check your .env file for SUPABASE_URL and SUPABASE_KEY and network connection.\n")
    else:
        # Consider port from environment variable for flexibility
        port = int(os.environ.get('PORT', 5000))
        # Turn off debug mode for production
        debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
        print(f"Starting Flask app on port {port} with debug={debug_mode}")
        app.run(debug=debug_mode, host='0.0.0.0', port=port)