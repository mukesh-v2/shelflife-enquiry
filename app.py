from flask import Flask, render_template, request, redirect, url_for
from flask import jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
from collections import defaultdict
from datetime import datetime, timedelta
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re

app = Flask(__name__)
app.secret_key = 'admin321'  # Simple fixed secret key
socketio = SocketIO(app)

# MongoDB Configuration
uri = "mongodb+srv://maku:abcd@cluster0.nv8kq.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
client = MongoClient(uri)
db = client.shelf_life_studies

# Create initial admin user if needed
if db.users.count_documents({}) == 0:
    db.users.insert_one({
        'username': 'admin',
        'password_hash': generate_password_hash('admin123'),
        'role': 'admin',
        'created_at': datetime.utcnow()
    })

# Flask-Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALL_STAGES = [
    'Enquiry Received',
    'Qualified',
    'Contact Initiated',
    'Feasibility Check',
    'Protocol Sent',
    'Quotation Sent',
    'Negotiation Stage',
    'Converted',
    'Unqualified'
]

class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.username = user_data['username']
        self.role = user_data['role']

@login_manager.user_loader
def load_user(user_id):
    user_data = db.users.find_one({'_id': ObjectId(user_id)})
    return User(user_data) if user_data else None

@app.route('/')
def customer_form():
    return render_template('customer_form.html')

@app.route('/submit', methods=['POST'])
def submit_enquiry():
    try:
        enquiry = {
            'contact_info': {
                'company': request.form.get('company'),
                'contact_person': request.form.get('contact_person'),
                'designation': request.form.get('designation'),
                'phone': request.form.get('phone'),
                'email': request.form.get('email')
            },
            'product_info': {
                'name': request.form.get('product_name'),
                'ingredients': request.form.get('ingredients'),
                'category': request.form.get('category'),
                'packaging': request.form.get('packaging'),
                'quantity': request.form.get('quantity'),
                'dimensions': request.form.get('dimensions'),
                'storage_condition': request.form.getlist('storage_condition'),
                'temp_humidity': request.form.get('temp_humidity'),
                'expected_shelf_life': request.form.get('expected_shelf_life'),
                'process': request.form.get('process')
            },
            'study_details': {
                'testing_condition': request.form.get('testing_condition'),
                'reason': request.form.get('reason'),
                'analysis_type': request.form.getlist('analysis_type'),
                'label_claims': request.form.get('label_claims')
            },
            'current_stage': 'Enquiry Received',
            'created_at': datetime.utcnow(),
            'history': [{
                'stage': 'Enquiry Received',
                'date': datetime.utcnow(),
                'changed_by': 'Customer',
                'notes': 'Initial enquiry submitted'
            }]
        }
        
        db.enquiries.insert_one(enquiry)
        
        # Emit real-time update to clients
        socketio.emit('analytics_update', {
            'stats': {
                'total_enquiries': db.enquiries.count_documents({}),
                # Include other stats as needed
            }
            # Include other data as needed
        })
        
        return redirect(url_for('thank_you'))
    except Exception as e:
        return render_template('error.html', error=str(e))

@app.route('/thank_you')
def thank_you():
    return render_template('thank_you.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user_data = db.users.find_one({'username': request.form['username']})
        if user_data and check_password_hash(user_data['password_hash'], request.form['password']):
            user = User(user_data)
            login_user(user)
            return redirect(url_for('dashboard'))
        return render_template('login.html', error='Invalid credentials')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    query = {}
    # Get filter parameters from request arguments
    company_search = request.args.get('company', '') # Keep the search input
    company_filter = request.args.get('company_filter', '') # New dropdown filter
    product_filter = request.args.get('product_filter', '') # New dropdown filter
    stage_filter = request.args.get('stage', '')
    
    # Build query based on filters
    if company_search:
        # Use the search input for partial matching
        query['contact_info.company'] = {'$regex': company_search, '$options': 'i'}
    elif company_filter:
        # Use the dropdown filter for exact matching
        query['contact_info.company'] = company_filter
    
    if product_filter:
        query['product_info.name'] = product_filter
    
    if stage_filter:
        query['current_stage'] = stage_filter
    
    # Fetch all enquiries to get unique values for dropdowns
    all_enquiries = list(db.enquiries.find({}))
    unique_companies = sorted(list(set([e['contact_info']['company'] for e in all_enquiries if 'contact_info' in e and 'company' in e['contact_info']]))) if all_enquiries else []
    unique_products = sorted(list(set([e['product_info']['name'] for e in all_enquiries if 'product_info' in e and 'name' in e['product_info']]))) if all_enquiries else []

    # Fetch filtered enquiries
    enquiries = list(db.enquiries.find(query).sort('created_at', -1))

    return render_template('sales_dashboard.html',
                         enquiries=enquiries,
                         unique_companies=unique_companies,
                         unique_products=unique_products,
                         request=request) # Pass request object to access args in template

@app.route('/enquiry/<id>')
@login_required
def enquiry_detail(id):
    enquiry = db.enquiries.find_one({'_id': ObjectId(id)})
    return render_template('enquiry_detail.html',
                         enquiry=enquiry,
                         all_stages=ALL_STAGES)

@app.route('/update_stage/<id>', methods=['POST'])
@login_required
def update_stage(id):
    new_stage = request.form['new_stage']
    notes = request.form['notes']
    
    enquiry = db.enquiries.find_one({'_id': ObjectId(id)})
    
    # Allow any stage transition
    db.enquiries.update_one(
        {'_id': ObjectId(id)},
        {'$set': {'current_stage': new_stage},
         '$push': {'history': {
             'stage': new_stage,
             'date': datetime.utcnow(),
             'changed_by': current_user.username,
             'notes': notes
         }}}
    )
    return redirect(url_for('enquiry_detail', id=id))

@app.route('/analytics')
@login_required
def analytics():
    categories = db.enquiries.distinct("product_info.category")
    return render_template('analytics.html', categories=categories)

@app.route('/analytics/data')
@login_required
def analytics_data():
    # Get filter parameters
    days = request.args.get('days', '30')
    category = request.args.get('category', 'all')
    
    # Calculate date range
    end_date = datetime.utcnow()
    if days == 'all':
        start_date = datetime(2000, 1, 1)  # Very old date
    else:
        start_date = end_date - timedelta(days=int(days))
    
    # Build query based on filters
    query = {"created_at": {"$gte": start_date}}
    if category != 'all':
        query["product_info.category"] = category
    
    # Get all enquiries
    enquiries = list(db.enquiries.find(query))
    
    # Calculate statistics
    total_enquiries = len(enquiries)
    converted_enquiries = [e for e in enquiries if e['current_stage'] == 'Converted']
    converted = len(converted_enquiries)
    conversion_rate = round((converted / total_enquiries * 100) if total_enquiries > 0 else 0, 1)
    active_enquiries_count = sum(1 for e in enquiries if e['current_stage'] not in ['Converted', 'Unqualified'])

    # Calculate average response time for converted enquiries
    total_response_time = timedelta(0)
    converted_count = 0
    for enquiry in converted_enquiries:
        created_at = enquiry.get('created_at')
        # Find the 'Converted' stage in history to get conversion date
        converted_date = None
        for history_item in enquiry.get('history', []):
            if history_item.get('stage') == 'Converted':
                converted_date = history_item.get('date')
                break
        
        if created_at and converted_date:
            time_to_convert = converted_date - created_at
            total_response_time += time_to_convert
            converted_count += 1

    avg_response_seconds = (total_response_time.total_seconds() / converted_count) if converted_count > 0 else 0
    # Convert seconds to a more readable format, e.g., hours or days
    # For simplicity, let's represent it in hours for now
    avg_response_hours = round(avg_response_seconds / 3600, 1)

    # Calculate trends
    # Define previous period (e.g., same duration as current period, but shifted back)
    if days == 'all':
        # For 'all' data, trends are not meaningful without a defined period
        prev_total_enquiries = total_enquiries
        prev_converted = converted
        prev_active_enquiries = active_enquiries_count
        prev_avg_response_seconds = avg_response_seconds
    else:
        prev_end_date = start_date
        prev_start_date = end_date - timedelta(days=int(days)*2)
        prev_query = {"created_at": {"$gte": prev_start_date, "$lt": prev_end_date}}
        if category != 'all':
            prev_query["product_info.category"] = category
        
        prev_enquiries = list(db.enquiries.find(prev_query))
        prev_total_enquiries = len(prev_enquiries)
        prev_converted = sum(1 for e in prev_enquiries if e['current_stage'] == 'Converted')
        prev_active_enquiries = sum(1 for e in prev_enquiries if e['current_stage'] not in ['Converted', 'Unqualified'])

        # Calculate previous average response time
        prev_total_response_time = timedelta(0)
        prev_converted_count = 0
        for enquiry in prev_enquiries:
            created_at = enquiry.get('created_at')
            converted_date = None
            for history_item in enquiry.get('history', []):
                if history_item.get('stage') == 'Converted':
                    converted_date = history_item.get('date')
                    break
            if created_at and converted_date:
                time_to_convert = converted_date - created_at
                prev_total_response_time += time_to_convert
                prev_converted_count += 1
        prev_avg_response_seconds = (prev_total_response_time.total_seconds() / prev_converted_count) if prev_converted_count > 0 else 0

    def calculate_trend(current, previous, is_time=False):
        if previous == 0:
            return "N/A" if current == 0 else "+\u221e%" # Infinity symbol
        change = current - previous
        percentage_change = (change / previous) * 100
        if is_time:
            # For time, a negative change is good (faster)
            return f"{change/3600:.1f}h" if change < 0 else f"+{change/3600:.1f}h"
        return f"+{percentage_change:.1f}%" if percentage_change > 0 else f"{percentage_change:.1f}%"

    stats = {
        'total_enquiries': total_enquiries,
        'conversion_rate': conversion_rate,
        'avg_response': avg_response_hours,
        'active_enquiries': active_enquiries_count,
        'enquiry_trend': calculate_trend(total_enquiries, prev_total_enquiries),
        'conversion_trend': calculate_trend(conversion_rate, round((prev_converted / prev_total_enquiries * 100) if prev_total_enquiries > 0 else 0, 1)),
        'response_trend': calculate_trend(avg_response_seconds, prev_avg_response_seconds, is_time=True),
        'active_trend': calculate_trend(active_enquiries_count, prev_active_enquiries)
    }
    
    # Stage distribution data
    stage_counts = defaultdict(int)
    for e in enquiries:
        stage_counts[e['current_stage']] += 1
    stage_labels = list(stage_counts.keys())
    stage_data = list(stage_counts.values())
    
    # Category distribution data
    category_counts = defaultdict(int)
    for e in enquiries:
        category_counts[e['product_info']['category']] += 1
    category_labels = list(category_counts.keys())
    category_data = list(category_counts.values())
    
    # Timeline data (last 30 days)
    timeline_labels = []
    timeline_data = []
    current_date = start_date
    while current_date <= end_date:
        timeline_labels.append(current_date.strftime('%Y-%m-%d'))
        count = sum(1 for e in enquiries if 
                   e['created_at'].date() == current_date.date())
        timeline_data.append(count)
        current_date += timedelta(days=1)
    
    # Top products
    product_counts = defaultdict(int)
    for e in enquiries:
        product_counts[e['product_info']['name']] += 1
    top_products = sorted(product_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    product_labels = [p[0] for p in top_products]
    product_data = [p[1] for p in top_products]
    
    return jsonify({
        'stats': stats,
        'stage_labels': stage_labels,
        'stage_data': stage_data,
        'category_labels': category_labels,
        'category_data': category_data,
        'timeline_labels': timeline_labels,
        'timeline_data': timeline_data,
        'product_labels': product_labels,
        'product_data': product_data
    }) 

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error='Page not found')

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error='Internal server error')

@socketio.on('connect')
def handle_connect():
    print('Client connected')
    # Optionally emit initial data

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)