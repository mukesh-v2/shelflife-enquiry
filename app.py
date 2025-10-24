from flask import Flask, render_template, request, redirect, session, url_for
from flask import jsonify
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from pymongo import DESCENDING, MongoClient
from bson.objectid import ObjectId
from collections import defaultdict
from datetime import datetime, timedelta
from flask_socketio import SocketIO
from werkzeug.security import generate_password_hash, check_password_hash
from zoneinfo import ZoneInfo
import pandas as pd
from flask import send_file
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
    'Unqualified',
    'Converted',
    'Study Abandoned',
    'Payment Recieved',
    'Report Generated'
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
def splash():
    # Render loading.html immediately
    return render_template('loading.html')
# (JS inside loading.html will redirect to /customer_form after a short delay)

# 2) Move your old “customer_form” route to /customer_form
from flask import request, jsonify, render_template, url_for, redirect

from flask import request, jsonify, redirect, url_for, render_template

@app.route('/customer_form', methods=['GET', 'POST'])
def customer_form():
    if request.method == 'POST':
        try:
            data = request.get_json()
            print("💡 Received data:", data)  # Add this for debugging

            # Contact info
            contact_info = data.get('contact_info', {})
            if not contact_info:
                return jsonify({'status': 'error', 'message': 'Missing contact information'}), 400

            # Products
            products = data.get('products', [])
            if not isinstance(products, list):
                return jsonify({'status': 'error', 'message': 'Invalid format: products must be a list'}), 400

            for product in products:
                if not isinstance(product, dict):
                    return jsonify({'status': 'error', 'message': 'Each product must be a dictionary'}), 400
                product['created_at'] = datetime.now(ZoneInfo("Asia/Kolkata"))
                product['status'] = 'Received'

            guide_by=data.get('guide','')
            # Insert
            enquiry_doc = {
                "contact_info": contact_info,
                "products": products,
                "created_at": datetime.now(ZoneInfo("Asia/Kolkata")),
                'current_stage': 'Enquiry Received',
                "guide_by":guide_by,
                'history': [{
                'stage': 'Enquiry Received',
                'date': datetime.now(ZoneInfo("Asia/Kolkata")),
                'changed_by': 'Customer',
                'notes': 'Initial enquiry submitted'
            }]
            }

            db.enquiries.insert_one(enquiry_doc)

            return jsonify({'status': 'success', 'redirect_url': url_for('thank_you')})

        except Exception as e:
            import traceback
            traceback.print_exc()
            return jsonify({'status': 'error', 'message': str(e)}), 500

    return render_template('customer_form.html')


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
            session['username'] = request.form['username']
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
    company_search = request.args.get('company', '')
    company_filter = request.args.get('company_filter', '')
    product_filter = request.args.get('product_filter', '')
    stage_filter = request.args.get('stage', '')
    username = session.get('username')
    ADMIN_USERS = ['admin','admin1',"manasi.d","mukesh.a","soumya.n","rahul.j","reshmi.n","chunmei.c"]
    if username not in ADMIN_USERS:
        query['guide_by'] = username 
    

    # Build MongoDB query
    if company_search:
        query['contact_info.company'] = {'$regex': company_search, '$options': 'i'}
    elif company_filter:
        query['contact_info.company'] = company_filter

    if product_filter:
        query['products.product_name'] = product_filter  # ✅ Corrected field

    if stage_filter:
        query['current_stage'] = stage_filter

    # Pagination parameters
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 10))
    
    # Calculate skip value for pagination
    skip = (page - 1) * per_page

    # Get total count for pagination
    total_enquiries = db.enquiries.count_documents(query)
    
    # Calculate pagination info
    total_pages = (total_enquiries + per_page - 1) // per_page
    has_prev = page > 1
    has_next = page < total_pages

    # Calculate showing range
    showing_from = ((page - 1) * per_page) + 1
    showing_to = min(page * per_page, total_enquiries)
    
    # Calculate pagination range for template
    start_page = max(1, page - 2)
    end_page = min(total_pages, page + 2)

    # Fetch filtered enquiries with pagination
    enquiries = list(db.enquiries.find(query).sort([('created_at', -1)]).skip(skip).limit(per_page))

    # Get unique companies for filter dropdown
    all_enquiries = list(db.enquiries.find({}))
    unique_companies = sorted(list(set(
        [e['contact_info']['company'] for e in all_enquiries if 'contact_info' in e and 'company' in e['contact_info']]
    ))) if all_enquiries else []

    # Get unique product names across all products
    unique_products = sorted(list(set(
        [p['product_name'] for e in all_enquiries if 'products' in e for p in e['products'] if 'product_name' in p]
    ))) if all_enquiries else []
    
  
    # ✅ Render template with raw MongoDB objects and pagination info
    return render_template('sales_dashboard.html',
                           enquiries=enquiries,
                           unique_companies=unique_companies,
                           unique_products=unique_products,
                           request=request,
                           page=page,
                           per_page=per_page,
                           total_pages=total_pages,
                           total_enquiries=total_enquiries,
                           has_prev=has_prev,
                           has_next=has_next,
                           showing_from=showing_from,
                           showing_to=showing_to,
                           start_page=start_page,
                           end_page=end_page)



@app.route('/enquiry/<id>')
@login_required
def enquiry_detail(id):
    enquiry = db.enquiries.find_one({'_id': ObjectId(id)})
    
    username = session.get('username')
    ADMIN_USERS = ['admin','admin1',"manasi.d","mukesh.a","soumya.n","rahul.j","reshmi.n","chunmei.c"]
    if username not in ADMIN_USERS:
        return render_template('enquiry_details_non_admin.html',
                         enquiry=enquiry,
                         all_stages=ALL_STAGES)

    
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
             'date': datetime.now(ZoneInfo("Asia/Kolkata")),
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
def get_analytics_data():
    days = request.args.get('days')
    category = request.args.get('category')
    username = session.get('username')
    ADMIN_USERS = ['admin','admin1',"manasi.d","mukesh.a","soumya.n","rahul.j","reshmi.n","chunmei.c"]
    
    # Build base query
    query = {}
    if username not in ADMIN_USERS:
        query['guide_by'] = username
    
    # Apply date filter
    if days and days != "all":
        query["created_at"] = {
            "$gte": datetime.utcnow() - timedelta(days=int(days))
        }
    
    if category and category != "all":
        query["guide_by"] = category

    # Use MongoDB aggregation pipeline for efficient data processing
    pipeline = [
        {"$match": query},
        {
            "$group": {
                "_id": None,
                "total_enquiries": {"$sum": 1},
                'net_sales': {'$sum': {'$ifNull': ['$order_value', 0]}},
                "stage_counts": {
                    "$push": "$current_stage"
                },
                "timeline_data": {
                    "$push": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$created_at"
                        }
                    }
                },
                "products_data": {
                    "$push": "$products"
                },
                "history_data": {
                    "$push": "$history"
                }
            }
        },
        {
            "$project": {
                "total_enquiries": 1,
                "stage_counts": 1,
                "timeline_data": 1,
                "products_data": 1,
                "history_data": 1,
                "net_sales": 1
            }
        }
    ]
    
    result = list(db.enquiries.aggregate(pipeline))
    if result:
        data = result[0]
        net_sales = data.get('net_sales', 0)
    else:
        net_sales = 0
    if not result:
        return jsonify({
            "stats": {
                "total_enquiries": 0,
                "conversion_rate": 0,
                "avg_response": 0,
                "active_enquiries": 0,
                "enquiry_trend": "+0%",
                "conversion_trend": "+0%",
                "response_trend": "+0%",
                "active_trend": "+0%",
                'net_sales': 0
            },
            "stage_labels": [],
            "stage_data": [],
            "category_labels": [],
            "category_data": [],
            "timeline_labels": [],
            "timeline_data": [],
            "product_labels": [],
            "product_data": []
        })
    
    data = result[0]
    total_enquiries = data['total_enquiries']
    
    # Process stage counts efficiently
    stage_counts = {}
    for stage in data['stage_counts']:
        stage_counts[stage] = stage_counts.get(stage, 0) + 1
    
    # Process timeline efficiently
    timeline = {}
    for date_str in data['timeline_data']:
        timeline[date_str] = timeline.get(date_str, 0) + 1
    
    # Process products efficiently
    category_counts = {}
    product_counts = {}
    for products in data['products_data']:
        for product in products:
            cat = product.get("category", "Uncategorized")
            category_counts[cat] = category_counts.get(cat, 0) + 1
            name = product.get("product_name", "Unnamed")
            product_counts[name] = product_counts.get(name, 0) + 1
    
    # Process active enquiries and conversion rate efficiently
    INACTIVE_STAGES = {"Converted", "Payment Recieved", "Unqualified", "Study Abandoned", "Report Generated"}
    CONVERTED_STAGES = {"Converted", "Payment Received", "Report Generated"}
    
    active_enquiries = 0
    converted_count = 0
    response_times = []
    
    for history in data['history_data']:
        if history:
            last_stage = history[-1].get("stage")
            if last_stage not in INACTIVE_STAGES:
                active_enquiries += 1
            if last_stage in CONVERTED_STAGES:
                converted_count += 1
            
            # Calculate response time
            if len(history) >= 2:
                stage0_time = history[0].get("date")
                stage1_time = history[1].get("date")
                if stage0_time and stage1_time:
                    t1 = stage0_time if isinstance(stage0_time, datetime) else datetime.fromisoformat(stage0_time)
                    t2 = stage1_time if isinstance(stage1_time, datetime) else datetime.fromisoformat(stage1_time)
                    delta = (t2 - t1).total_seconds() / 3600
                    response_times.append(delta)
        else:
            active_enquiries += 1
    
    # Calculate metrics
    conversion_rate = round(converted_count / total_enquiries * 100, 2) if total_enquiries else 0
    avg_response = round(sum(response_times) / len(response_times), 2) if response_times else 0
    
    # Get trends (simplified - you might want to cache this)
    prev_trend = db.trends.find_one(
        {"username": username, "days": days, "category": category},
        sort=[("date", DESCENDING)]
    )
    
    def trend_percent(new, old):
        if old == 0:
            return "+0%"
        change = ((new - old) / old) * 100 if old else 0
        sign = "+" if change >= 0 else "-"
        return f"{sign}{abs(round(change))}%"
    
    if prev_trend:
        enquiry_trend = trend_percent(total_enquiries, prev_trend.get("total_enquiries", 0))
        conversion_trend = trend_percent(conversion_rate, prev_trend.get("conversion_rate", 0))
        response_trend = trend_percent(avg_response, prev_trend.get("avg_response", 0))
        active_trend = trend_percent(active_enquiries, prev_trend.get("active_enquiries", 0))
    else:
        enquiry_trend = conversion_trend = response_trend = active_trend = "+0%"
    
    # Save current trends
    db.trends.insert_one({
        "date": datetime.utcnow(),
        "username": username,
        "days": days,
        "category": category,
        "total_enquiries": total_enquiries,
        "conversion_rate": conversion_rate,
        "avg_response": avg_response,
        "active_enquiries": active_enquiries,
        "enquiry_trend": enquiry_trend,
        "conversion_trend": conversion_trend,
        "response_trend": response_trend,
        "active_trend": active_trend
    })
    
    # Generate timeline data efficiently
    if days and days != "all":
        start_date = (datetime.utcnow() - timedelta(days=int(days))).date()
    else:
        if timeline:
            start_date = min(datetime.strptime(d, "%Y-%m-%d").date() for d in timeline.keys())
        else:
            start_date = datetime.utcnow().date()
    
    end_date = datetime.utcnow().date()
    full_dates = []
    filled_timeline = []
    delta = (end_date - start_date).days
    for i in range(delta + 1):
        day = start_date + timedelta(days=i)
        date_str = day.strftime("%Y-%m-%d")
        full_dates.append(date_str)
        filled_timeline.append(timeline.get(date_str, 0))
    
    return jsonify({
        "stats": {
            "total_enquiries": total_enquiries,
            "conversion_rate": conversion_rate,
            "avg_response": avg_response,
            "active_enquiries": active_enquiries,
            "enquiry_trend": enquiry_trend,
            "conversion_trend": conversion_trend,
            "response_trend": response_trend,
            "active_trend": active_trend,
            'net_sales': net_sales
        },
        "stage_labels": list(stage_counts.keys()),
        "stage_data": list(stage_counts.values()),
        "category_labels": list(category_counts.keys()),
        "category_data": list(category_counts.values()),
        "timeline_labels": full_dates,
        "timeline_data": filled_timeline,
        "product_labels": list(product_counts.keys()),
        "product_data": list(product_counts.values())
    })

    


@app.route('/api/enquiries', methods=['POST'])
def create_enquiry():
    data = request.get_json()

    now = datetime.utcnow()

    # Set timestamps and defaults
    data['created_at'] = now
    data['current_stage'] = "Enquiry Received"
    
    for product in data.get('products', []):
        product['created_at'] = now
        product['status'] = "Received"

    data['history'] = [{
        "stage": "Enquiry Received",
        "date": now,
        "changed_by": "Customer",
        "notes": "Initial enquiry submitted"
    }]

    # Insert into MongoDB
    db.enquiries.insert_one(data)

    return jsonify({"message": "Enquiry submitted successfully"}), 201

from pytz import timezone, utc


@app.template_filter('to_ist')
def to_ist(dt):
    if not dt or not isinstance(dt, datetime):
        return "N/A"
    
    ist = timezone('Asia/Kolkata')

    # Make naive datetime timezone-aware (assume it's in UTC)
    if dt.tzinfo is None:
        dt = utc.localize(dt)
    
    return dt.astimezone(ist).strftime('%Y-%m-%d %H:%M')

@app.route("/update-guide", methods=["POST"])
def update_guide():
    data = request.get_json()
    enquiry_id = data["enquiry_id"]
    new_guide = data["guide_by"]

    # Update the document and append to history
    db.enquiries.update_one(
        {"_id": ObjectId(enquiry_id)},
        {
            "$set": {
                "guide_by": new_guide
            },
        }
    )
    return jsonify({"updated_value": new_guide}), 200

@app.route('/update-order-value', methods=['POST'])
@login_required
def update_order_value():
    data = request.get_json()
    enquiry_id = data.get('enquiry_id', '').strip()
    order_value = float(data.get('order_value', 0))  # default 0

    if not enquiry_id or len(enquiry_id) != 24:
        return jsonify({'error': 'Invalid enquiry_id'}), 400
    try:
        result = db.enquiries.update_one({'_id': ObjectId(enquiry_id)}, {'$set': {'order_value': order_value}})
        if result.modified_count == 1:
            return jsonify({'updated_value': order_value}), 200
        else:
            return jsonify({'error': 'No record updated'}), 400
    except Exception as e:
        return jsonify({'error': str(e)}), 500 

@app.route('/mis-report.xlsx', methods=['GET'])
@login_required
def mis_report():
    # Parse date range from query params
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    query = {}
    # Filter by created_at if dates provided
    if start_date and end_date:
        query['created_at'] = {
            '$gte': datetime.strptime(start_date, "%Y-%m-%d"),
            '$lte': datetime.strptime(end_date, "%Y-%m-%d")
        }

    enquiries = list(db.enquiries.find(query))
    rows = []
    for enquiry in enquiries:
        # Flatten info, handle missing fields
        row = {
            'Enquiry ID': str(enquiry.get('_id', '')),
            'Company': enquiry.get('contact_info', {}).get('company', ''),
            'Contact Person': enquiry.get('contact_info', {}).get('person', ''),
            'Designation': enquiry.get('contact_info', {}).get('designation', ''),
            'Phone': enquiry.get('contact_info', {}).get('phone', ''),
            'Email': enquiry.get('contact_info', {}).get('email', ''),
            'Guide': enquiry.get('guide_by', ''),
            'Order Value': enquiry.get('order_value', ''),
            'Current Stage': enquiry.get('current_stage', ''),
            'Created At': enquiry.get('created_at', ''),
        }
        # Products: flatten all products into string
        products = enquiry.get('products', [])
        row['Products'] = '; '.join(
            [f"{p.get('product_name', '')} ({p.get('category', '')}, {p.get('sample_qty', '')})"
             for p in products]
        )
        # History: flatten all changes
        histories = enquiry.get('history', [])
        row['History'] = '; '.join(
            [f"{h.get('stage', '')} @ {h.get('date', '')} by {h.get('changed_by','')}" 
             for h in histories]
        )
        rows.append(row)
    import pandas as pd
    df = pd.DataFrame(rows)
    filename = 'mis_report.xlsx'
    df.to_excel(filename, index=False)
    from flask import send_file
    return send_file(filename, as_attachment=True)

@app.route('/mis-export')
@login_required
def mis_export_ui():
    return render_template('mis_report_download.html')

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
