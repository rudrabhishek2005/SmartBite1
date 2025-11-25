# app.py

from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import os
from datetime import datetime, timedelta
import uuid
from azure.cognitiveservices.vision.computervision import ComputerVisionClient
from azure.cognitiveservices.vision.computervision.models import OperationStatusCodes
from msrest.authentication import CognitiveServicesCredentials
import re
import time
import tempfile
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
import mimetypes
import threading
import requests
from azure.core.credentials import AzureKeyCredential
from azure.search.documents import SearchClient
from azure.search.documents.models import QueryType
from azure.search.documents.models import VectorizedQuery
import logging
from sqlalchemy import text
import json
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

# Azure Cognitive Search configuration
AZURE_SEARCH_ENDPOINT = os.getenv("AZURE_SEARCH_ENDPOINT", "https://your-search-service.search.windows.net")
AZURE_SEARCH_KEY = os.getenv("AZURE_SEARCH_KEY","")
AZURE_SEARCH_INDEX = "recipes-index"

search_client = SearchClient(
    endpoint=AZURE_SEARCH_ENDPOINT,
    index_name=AZURE_SEARCH_INDEX,
    credential=AzureKeyCredential(AZURE_SEARCH_KEY)
)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-change-this-in-production')
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max upload

# Create upload directory if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI', 'sqlite:///food_items.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Email configuration
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = os.getenv('MAIL_USE_TLS', 'True').lower() == 'true'
app.config['MAIL_USE_SSL'] = os.getenv('MAIL_USE_SSL', 'False').lower() == 'true'
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Explicit SMTP configuration provided by user (overrides env if present)
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'kolliparamithra84@gmail.com'
app.config['MAIL_PASSWORD'] = 'aool ykpf ruuu lkhy'
app.config['MAIL_DEFAULT_SENDER'] = ('SWASTYA AI', 'kolliparamithra84@gmail.com')

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)

# Azure Computer Vision client setup
AZURE_ENDPOINT = os.getenv("AZURE_VISION_ENDPOINT", "https://innovationday.cognitiveservices.azure.com/")
AZURE_KEY = os.getenv("AZURE_VISION_KEY","Efzim3ZVShBXONNmmU0BGWfvozbdsEUsKxfOXO7Ikh2qwDcExhyiJQQJ99BJACHYHv6XJ3w3AAAFACOGiJUX")
vision_client = ComputerVisionClient(
    AZURE_ENDPOINT,
    CognitiveServicesCredentials(AZURE_KEY)
)

# Azure OpenAI (Chatbot) configuration
AZURE_OAI_ENDPOINT = os.getenv("AZURE_OAI_ENDPOINT", "https://chatbotfood.openai.azure.com/")
AZURE_OAI_API_VERSION = os.getenv("AZURE_OAI_API_VERSION", "2025-01-01-preview")
AZURE_OAI_DEPLOYMENT = os.getenv("AZURE_OAI_DEPLOYMENT", "gpt-35-turbo")
AZURE_OAI_KEY = os.getenv("AZURE_OAI_KEY", "CwKaYKWM2lI2ojr8ZZr3m607qI62AMKuR18wqNb8gShMcCwNH3h5JQQJ99BJACYeBjFXJ3w3AAABACOGuCGQ")

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship to food items
    food_items = db.relationship('FoodItem', backref='user', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def __repr__(self):
        return f'<User {self.username}>'

# Define the FoodItem model
class FoodItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    expiry_date = db.Column(db.String(20), nullable=False)
    parsed_date = db.Column(db.Date, nullable=False)
    user_email = db.Column(db.String(100), nullable=False)
    notification_days = db.Column(db.Integer, default=3)
    image_path = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_custom = db.Column(db.Boolean, default=False)  # True for manually added items
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)  # Link to user

    def __repr__(self):
        return f'<FoodItem {self.name}>'

# Authentication decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Create the database tables
with app.app_context():
    db.create_all()
    # Ensure a default sender exists if not explicitly configured
    if not app.config.get('MAIL_DEFAULT_SENDER') and app.config.get('MAIL_USERNAME'):
        app.config['MAIL_DEFAULT_SENDER'] = app.config['MAIL_USERNAME']

    # Database migration: Handle existing data without user_id
    try:
        # Check if user_id column exists in FoodItem table
        result = db.session.execute(text("PRAGMA table_info(food_item)"))
        columns = [row[1] for row in result.fetchall()]
        
        if 'user_id' not in columns:
            print("Adding user_id column to FoodItem table...")
            # Add user_id column
            db.session.execute(text("ALTER TABLE food_item ADD COLUMN user_id INTEGER"))
            
            # Create a default user for existing data
            default_user = User(
                username='default_user',
                email='default@example.com'
            )
            default_user.set_password('default_password')
            db.session.add(default_user)
            db.session.commit()
            
            # Update existing food items to belong to default user
            db.session.execute(text("UPDATE food_item SET user_id = 1 WHERE user_id IS NULL"))
            db.session.commit()
            print("Migration completed successfully!")
    except Exception as e:
        print(f"Migration error: {e}")
        db.session.rollback()

    # Ensure "notified" and "is_custom" columns exist
    try:
        result = db.session.execute(text("PRAGMA table_info(food_item)"))
        cols = [row[1] for row in result]
        if 'notified' not in cols:
            db.session.execute(text("ALTER TABLE food_item ADD COLUMN notified INTEGER DEFAULT 0"))
            db.session.commit()
        if 'is_custom' not in cols:
            db.session.execute(text("ALTER TABLE food_item ADD COLUMN is_custom INTEGER DEFAULT 0"))
            db.session.commit()
    except Exception as e:
        app.logger.warning(f"Could not ensure columns: {e}")

# List of common date patterns for regex matching
MFG_DATE_PATTERNS = [
    r"(?:MFG|Mfg|mfg|Manufacturing|MANUFACTURING|Date of Manufacture|DOM|Production|PRODUCTION)\.?\s*:?\s*(\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4})",
    r"(?:MFG|Mfg|mfg|Manufacturing|MANUFACTURING|Date of Manufacture|DOM|Production|PRODUCTION)\.?\s*:?\s*(\d{2}[-/\.]\s*[A-Za-z]{3}[-/\.]\s*\d{2,4})",
    r"(?:MFG|Mfg|mfg|Manufacturing|MANUFACTURING|Date of Manufacture|DOM|Production|PRODUCTION)\.?\s*:?\s*([A-Za-z]{3}[-/\.]\s*\d{4})"
]

EXPIRY_DATE_PATTERNS = [
    r"(?:EXP|Exp|exp|Expiry|EXPIRY|Best Before|USE BY|Use By|BBE)\.?\s*:?\s*(\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4})",
    r"(?:EXP|Exp|exp|Expiry|EXPIRY|Best Before|BBE)\.?\s*:?\s*(\d{2}[-/\.]\s*[A-Za-z]{3}[-/\.]\s*\d{2,4})",
    r"(?:EXP|Exp|exp|Expiry|EXPIRY|Best Before|BBE)\.?\s*:?\s*([A-Za-z]{3}[-/\.]\s*\d{4})"
]

GENERIC_DATE_PATTERN = r"(\d{1,2}[-/\.]\d{1,2}[-/\.]\d{2,4})"

# Function to check if an item with the same name already exists for current user
def item_exists(food_name, user_id):
    return db.session.query(FoodItem).filter_by(name=food_name, user_id=user_id).first() is not None

# Function to send email asynchronously
def send_async_email(app, msg):
    with app.app_context():
        try:
            mail.send(msg)
        except Exception as e:
            app.logger.error(f"Email send failed: {e}")

# Function to send expiry notification email
def send_expiry_notification(food_item):
    msg = Message(
        subject=f"Food Expiry Alert: {food_item.name}",
        recipients=[food_item.user_email]
    )
    msg.body = f"""
Hello,

This is a reminder that your food item "{food_item.name}" is expiring soon on {food_item.expiry_date}.

You are receiving this notification {food_item.notification_days} days before expiry as requested.

Please consume it before it expires to avoid food waste.

Best regards,
Food Expiry Tracker
"""
    # Attach uploaded photo if available
    try:
        if getattr(food_item, 'image_path', None):
            # image_path is stored without the leading 'static/' in DB
            candidate_path = food_item.image_path
            if not candidate_path:
                candidate_path = ""
            # Build absolute path under static
            file_path = os.path.join('static', candidate_path) if not candidate_path.startswith('static') else candidate_path
            if os.path.exists(file_path) and os.path.isfile(file_path):
                mime_type, _ = mimetypes.guess_type(file_path)
                mime_type = mime_type or 'application/octet-stream'
                with open(file_path, 'rb') as f:
                    msg.attach(os.path.basename(file_path), mime_type, f.read())
    except Exception as e:
        app.logger.warning(f"Could not attach image to email for item {food_item.id if food_item else 'unknown'}: {e}")
    # Send email asynchronously
    threading.Thread(target=send_async_email, args=[app, msg]).start()
    return True

def check_and_send_notifications():
    """Check items nearing expiry and send email notifications once."""
    with app.app_context():
        try:
            today = datetime.now().date()
            items = FoodItem.query.all()
            for item in items:
                try:
                    days_left = (item.parsed_date - today).days
                    # Only notify for items not yet notified and not already expired by more than 0 days
                    # and within the user's notification window
                    # Access "notified" column via raw SQL fallback if attribute missing
                    notified_val = getattr(item, 'notified', None)
                    if notified_val is None:
                        # Column may not be mapped on the model; fetch via query
                        row = db.session.execute(text("SELECT notified FROM food_item WHERE id=:id"), {"id": item.id}).fetchone()
                        notified_val = (row[0] if row is not None else 0)

                    if days_left <= item.notification_days and days_left >= 0 and not notified_val:
                        if send_expiry_notification(item):
                            try:
                                db.session.execute(
                                    text("UPDATE food_item SET notified=1 WHERE id=:id"),
                                    {"id": item.id}
                                )
                                db.session.commit()
                            except Exception as e:
                                app.logger.error(f"Failed to mark item notified (id={item.id}): {e}")
                except Exception as e:
                    app.logger.error(f"Notification check failed for item {item.id if item else 'unknown'}: {e}")
        except Exception as e:
            app.logger.error(f"Notification sweep failed: {e}")

def start_notification_worker():
    """Start a background worker that periodically checks for expiring items."""
    def worker():
        while True:
            try:
                check_and_send_notifications()
            except Exception as e:
                app.logger.error(f"Notification worker error: {e}")
            time.sleep(60 * 60)  # run hourly

    t = threading.Thread(target=worker, daemon=True)
    t.start()

def _masked_mail_config():
    """Return mail config with sensitive fields masked for diagnostics."""
    return {
        'MAIL_SERVER': app.config.get('MAIL_SERVER'),
        'MAIL_PORT': app.config.get('MAIL_PORT'),
        'MAIL_USE_TLS': app.config.get('MAIL_USE_TLS'),
        'MAIL_USE_SSL': app.config.get('MAIL_USE_SSL'),
        'MAIL_USERNAME': (app.config.get('MAIL_USERNAME')[:2] + '***') if app.config.get('MAIL_USERNAME') else None,
        'MAIL_DEFAULT_SENDER': app.config.get('MAIL_DEFAULT_SENDER'),
        'HAS_PASSWORD': bool(app.config.get('MAIL_PASSWORD'))
    }

@app.route('/admin/mail-config', methods=['GET'])
def admin_mail_config():
    """Non-sensitive view of current mail config to help debugging."""
    return jsonify({ 'success': True, 'config': _masked_mail_config() })

@app.route('/admin/test-email', methods=['POST'])
def admin_test_email():
    try:
        data = request.get_json(silent=True) or {}
        recipient = data.get('to')
        if not recipient:
            return jsonify({ 'success': False, 'message': 'Missing to' }), 400
        msg = Message(subject='Food Expiry Tracker - Test Email', recipients=[recipient])
        msg.body = 'This is a test email from Food Expiry Tracker. If you received this, SMTP is configured.'
        send_async_email(app, msg)
        return jsonify({ 'success': True, 'message': 'Test email queued', 'config': _masked_mail_config() })
    except Exception as e:
        return jsonify({ 'success': False, 'message': f'Error: {str(e)}' }), 500

def extract_dates(text):
    """Extract both manufacturing and expiry dates from OCR text."""
    # Find manufacturing date
    mfg_date = None
    for pattern in MFG_DATE_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            mfg_date = matches[0]
            break

    # Find expiry date
    exp_date = None
    for pattern in EXPIRY_DATE_PATTERNS:
        matches = re.findall(pattern, text)
        if matches:
            exp_date = matches[0]
            break

    # If no explicit expiry date found, look for any dates
    if not exp_date:
        # Get all generic dates
        all_dates = re.findall(GENERIC_DATE_PATTERN, text)
        # If we have multiple dates and one is manufacturing
        if len(all_dates) >= 2:
            # If manufacturing date is identified, find a date that comes after it
            if mfg_date and mfg_date in all_dates:
                # Get the index of manufacturing date
                mfg_index = all_dates.index(mfg_date)
                # Assume the next date after manufacturing is expiry
                if mfg_index < len(all_dates) - 1:
                    exp_date = all_dates[mfg_index + 1]
                    # Verify expiry date is later than manufacturing date
                    if not compare_dates(mfg_date, exp_date):
                        exp_date = None
            else:
                # If no manufacturing date identified, take the last date as expiry
                exp_date = all_dates[-1]

    return mfg_date, exp_date

def parse_date(date_str):
    """Try to parse the extracted date string into a standardized format."""
    try:
        # Remove any spaces in the date string
        date_str = re.sub(r'\s+', '', date_str)
        
        # Try different date parsing formats
        formats = [
            '%d/%m/%Y', '%d/%m/%y', '%m/%d/%Y', '%m/%d/%y',
            '%d-%m-%Y', '%d-%m-%y', '%m-%d-%Y', '%m-%d-%y',
            '%d.%m.%Y', '%d.%m.%y', '%m.%d.%Y', '%m.%d.%y',
            '%b%Y', '%b%y', '%B%Y', '%B%y',
            '%d%b%Y', '%d%b%y', '%d%B%Y', '%d%B%y'
        ]
        
        for fmt in formats:
            try:
                date_obj = datetime.strptime(date_str, fmt)
                return date_obj.strftime('%Y-%m-%d')
            except ValueError:
                continue
        
        return date_str  # Return the original if parsing fails
    except Exception as e:
        print(f"Error parsing date: {e}")
        return date_str

def compare_dates(mfg_date_str, exp_date_str):
    """Compare manufacturing and expiry dates to ensure expiry is later."""
    if not mfg_date_str or not exp_date_str:
        return True  # If one date is missing, we can't compare
    
    try:
        mfg_parsed = parse_date(mfg_date_str)
        exp_parsed = parse_date(exp_date_str)
        
        mfg_date = datetime.strptime(mfg_parsed, '%Y-%m-%d')
        exp_date = datetime.strptime(exp_parsed, '%Y-%m-%d')
        
        # Return True if expiry date is after manufacturing date
        return exp_date > mfg_date
    except:
        # If dates couldn't be parsed properly, we can't compare
        return True

def process_image(image_path):
    """Process image through Azure Computer Vision to extract text."""
    try:
        # Open the image file
        with open(image_path, "rb") as image_file:
            # Call the Azure OCR API
            read_response = vision_client.read_in_stream(image_file, raw=True)
            
            # Get the operation location from the response
            operation_location = read_response.headers["Operation-Location"]
            operation_id = operation_location.split("/")[-1]
            
            # Wait for the OCR operation to complete
            while True:
                read_result = vision_client.get_read_result(operation_id)
                if read_result.status not in [OperationStatusCodes.running, OperationStatusCodes.not_started]:
                    break
                time.sleep(1)
            
            # Extract text from the OCR results
            extracted_text = ""
            if read_result.status == OperationStatusCodes.succeeded:
                for text_result in read_result.analyze_result.read_results:
                    for line in text_result.lines:
                        extracted_text += line.text + "\n"
                
                # Extract both manufacturing and expiry dates
                mfg_date, exp_date = extract_dates(extracted_text)
                
                # If we have both dates, validate that expiry is after manufacturing
                if mfg_date and exp_date:
                    is_valid = compare_dates(mfg_date, exp_date)
                    if not is_valid:
                        return {
                            "success": False,
                            "raw_text": extracted_text,
                            "message": "Invalid expiry date: Expiry date is earlier than manufacturing date."
                        }
                
                if exp_date:
                    parsed_date = parse_date(exp_date)
                    return {
                        "success": True,
                        "raw_text": extracted_text,
                        "expiry_date": exp_date,
                        "parsed_date": parsed_date,
                        "manufacturing_date": mfg_date if mfg_date else "Not detected"
                    }
                else:
                    return {
                        "success": False,
                        "raw_text": extracted_text,
                        "message": "No expiry date found in the image."
                    }
    except Exception as e:
        return {
            "success": False,
            "message": f"Error processing image: {str(e)}"
        }

# Authentication routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['username'] = user.username
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'error')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not username or not email or not password:
            flash('All fields are required', 'error')
            return render_template('register.html')
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return render_template('register.html')
        
        # Check if user already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'error')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'error')
            return render_template('register.html')
        
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        try:
            db.session.add(user)
            db.session.commit()
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            db.session.rollback()
            flash('Registration failed. Please try again.', 'error')
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    return render_template('index.html')

@app.route('/remove_item/<int:item_id>', methods=['POST'])
@login_required
def remove_item(item_id):
    try:
        # Get the item from database and ensure it belongs to current user
        item = FoodItem.query.filter_by(id=item_id, user_id=session['user_id']).first()
        if not item:
            return jsonify({"success": False, "message": "Item not found or access denied"}), 404
        
        # Get the image path to delete the file
        image_path = os.path.join('static', item.image_path)
        
        # Delete the item from database
        db.session.delete(item)
        db.session.commit()
        
        # Delete the image file if it exists
        if os.path.exists(image_path):
            os.remove(image_path)
        
        # Redirect back to the saved items page
        return redirect(url_for('saved_items'))
    except Exception as e:
        return jsonify({"success": False, "message": f"Error removing item: {str(e)}"}), 500

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"success": False, "message": "No file part"})
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({"success": False, "message": "No selected file"})
    
    if file:
        # Generate a unique filename
        file_extension = os.path.splitext(file.filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        # Save the file
        file.save(file_path)
        
        # Process the image
        result = process_image(file_path)
        
        # Add the image path to the result
        result["image_path"] = file_path.replace("static/", "")
        
        return jsonify(result)

@app.route('/capture', methods=['POST'])
@login_required
def capture_image():
    if 'image' not in request.files:
        return jsonify({"success": False, "message": "No image data"})
    
    file = request.files['image']
    
    # Save the captured image to a temporary file
    with tempfile.NamedTemporaryFile(delete=False, suffix='.jpg', dir=app.config['UPLOAD_FOLDER']) as temp:
        file.save(temp.name)
        temp_path = temp.name
    
    # Process the image
    result = process_image(temp_path)
    
    # Create a permanent filename for the image
    unique_filename = f"{uuid.uuid4()}.jpg"
    perm_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    # Rename the temporary file to the permanent file
    os.rename(temp_path, perm_path)
    
    # Add the image path to the result
    result["image_path"] = perm_path.replace("static/", "")
    
    return jsonify(result)

@app.route('/save-item', methods=['POST'])
@login_required
def save_item():
    try:
        data = request.json
        food_name = data.get('food_name')
        expiry_date = data.get('expiry_date')
        parsed_date = datetime.strptime(data.get('parsed_date'), '%Y-%m-%d').date()
        user_email = data.get('user_email')
        notification_days = int(data.get('notification_days', 3))
        image_path = data.get('image_path')
        force_add = data.get('force_add', False)  # New parameter to force add
        
        # Validate data
        if not all([food_name, expiry_date, parsed_date, user_email, image_path]):
            return jsonify({"success": False, "message": "Missing required fields"})
        
        # Check if item with same name exists for current user
        if item_exists(food_name, session['user_id']) and not force_add:
            return jsonify({
                "success": False, 
                "message": "duplicate",
                "duplicate": True,
                "food_name": food_name
            })
        
        # Create new food item
        new_item = FoodItem(
            name=food_name,
            expiry_date=expiry_date,
            parsed_date=parsed_date,
            user_email=user_email,
            notification_days=notification_days,
            image_path=image_path,
            user_id=session['user_id']
        )
        
        # Save to database
        db.session.add(new_item)
        db.session.commit()
        
        # Send notification if expiry date is within specified days
        today = datetime.now().date()
        days_until_expiry = (parsed_date - today).days
        if days_until_expiry <= notification_days:
            send_expiry_notification(new_item)
        
        return jsonify({"success": True, "message": "Food item saved successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

@app.route('/save-custom-item', methods=['POST'])
@login_required
def save_custom_item():
    try:
        data = request.json
        food_name = data.get('food_name')
        expiry_days = int(data.get('expiry_days'))
        user_email = data.get('user_email')
        notification_days = int(data.get('notification_days', 3))
        image_file = data.get('image_file')  # Base64 encoded image
        
        # Validate data
        if not all([food_name, expiry_days, user_email]):
            return jsonify({"success": False, "message": "Missing required fields"})
        
        # Calculate expiry date (today + expiry_days)
        today = datetime.now().date()
        expiry_date = today + timedelta(days=expiry_days)
        
        # Handle image upload if provided
        image_path = "default-food.png"  # Default image
        if image_file:
            try:
                # Decode base64 image
                import base64
                image_data = base64.b64decode(image_file.split(',')[1])
                file_extension = image_file.split(';')[0].split('/')[1]
                unique_filename = f"{uuid.uuid4()}.{file_extension}"
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
                
                with open(file_path, 'wb') as f:
                    f.write(image_data)
                image_path = file_path.replace("static/", "")
            except Exception as e:
                app.logger.warning(f"Failed to save custom image: {e}")
        
        # Create new custom food item
        new_item = FoodItem(
            name=food_name,
            expiry_date=f"{expiry_days} days",
            parsed_date=expiry_date,
            user_email=user_email,
            notification_days=notification_days,
            image_path=image_path,
            is_custom=True,
            user_id=session['user_id']
        )
        
        # Save to database
        db.session.add(new_item)
        db.session.commit()
        
        # Send notification if expiry date is within specified days
        days_until_expiry = (expiry_date - today).days
        if days_until_expiry <= notification_days:
            send_expiry_notification(new_item)
        
        return jsonify({"success": True, "message": "Custom food item saved successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"})

@app.route('/saved-items')
@login_required
def saved_items():
    # Get regular items (not custom) for current user
    regular_items = FoodItem.query.filter_by(is_custom=False, user_id=session['user_id']).order_by(FoodItem.parsed_date).all()
    regular_items_list = []
    
    for item in regular_items:
        regular_items_list.append({
            'id': item.id,
            'name': item.name,
            'expiry_date': item.expiry_date,
            'parsed_date': item.parsed_date.strftime('%Y-%m-%d'),
            'user_email': item.user_email,
            'notification_days': item.notification_days,
            'image_path': item.image_path,
            'days_left': (item.parsed_date - datetime.now().date()).days
        })
    
    # Get custom items for current user
    custom_items = FoodItem.query.filter_by(is_custom=True, user_id=session['user_id']).order_by(FoodItem.parsed_date).all()
    custom_items_list = []
    
    for item in custom_items:
        custom_items_list.append({
            'id': item.id,
            'name': item.name,
            'expiry_date': item.expiry_date,
            'parsed_date': item.parsed_date.strftime('%Y-%m-%d'),
            'user_email': item.user_email,
            'notification_days': item.notification_days,
            'image_path': item.image_path,
            'days_left': (item.parsed_date - datetime.now().date()).days
        })
    
    return render_template('saved_items.html', items=regular_items_list, custom_items=custom_items_list)

@app.route('/analyze-nutrition', methods=['POST'])
@login_required
def analyze_nutrition():
    import json
    import re
    import requests

    def off_by_barcode(barcode: str):
        url = f"https://world.openfoodfacts.org/api/v2/product/{barcode}.json"
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            return None
        data = r.json()
        if not data.get('product'):
            return None
        return data['product']

    def off_search_by_name(name: str):
        # Clean and normalize the search term
        clean_name = name.lower().strip()
        
        # Try multiple search strategies for better results
        search_terms = [clean_name]
        
        # Add common variations for basic foods
        if 'rice' in clean_name and 'cake' not in clean_name:
            search_terms.extend(['white rice', 'brown rice', 'basmati rice'])
        elif 'apple' in clean_name:
            search_terms.extend(['fresh apple', 'raw apple'])
        elif 'bread' in clean_name:
            search_terms.extend(['white bread', 'whole wheat bread'])
        
        for search_term in search_terms:
            params = {
                'search_terms': search_term,
                'search_simple': 1,
                'json': 1,
                'page_size': 3,  # Get more results to find the best match
                'fields': 'product_name,nutriments,serving_size,categories_tags'
            }
            r = requests.get('https://world.openfoodfacts.org/cgi/search.pl', params=params, timeout=10)
            if r.status_code != 200:
                continue
            data = r.json()
            prods = data.get('products') or []
            
            # Find the best match based on name similarity and category
            for prod in prods:
                prod_name = (prod.get('product_name') or '').lower()
                categories = prod.get('categories_tags') or []
                
                # Prefer products that match the original search term closely
                if clean_name in prod_name or any(clean_name in cat for cat in categories):
                    return prod
            
            # If no close match found, return the first result
            if prods:
                return prods[0]
        
        return None

    def map_off_to_response(product: dict):
        nutr = product.get('nutriments') or {}
        def fmt(val, unit=""):
            return (f"{val}{unit}" if val is not None else None)
        calories = nutr.get('energy-kcal_serving') or nutr.get('energy-kcal_100g')
        if calories is not None:
            calories = f"{round(float(calories),1)} kcal per {product.get('serving_size','100g')}"
        resp = {
            'product_name': product.get('product_name') or 'Unknown',
            'nutrition_facts': {
                'calories': calories or 'N/A',
                'total_fat': fmt(nutr.get('fat_serving') or nutr.get('fat_100g'), 'g') or 'N/A',
                'saturated_fat': fmt(nutr.get('saturated-fat_serving') or nutr.get('saturated-fat_100g'), 'g') or 'N/A',
                'cholesterol': fmt(nutr.get('cholesterol_serving') or nutr.get('cholesterol_100g'), 'mg') or 'N/A',
                'sodium': fmt(nutr.get('sodium_serving') or nutr.get('sodium_100g'), 'mg') or 'N/A',
                'total_carbohydrates': fmt(nutr.get('carbohydrates_serving') or nutr.get('carbohydrates_100g'), 'g') or 'N/A',
                'dietary_fiber': fmt(nutr.get('fiber_serving') or nutr.get('fiber_100g'), 'g') or 'N/A',
                'sugars': fmt(nutr.get('sugars_serving') or nutr.get('sugars_100g'), 'g') or 'N/A',
                'protein': fmt(nutr.get('proteins_serving') or nutr.get('proteins_100g'), 'g') or 'N/A',
                'vitamin_c': fmt(nutr.get('vitamin-c_serving') or nutr.get('vitamin-c_100g'), 'mg') or 'N/A',
                'calcium': fmt(nutr.get('calcium_serving') or nutr.get('calcium_100g'), 'mg') or 'N/A',
                'iron': fmt(nutr.get('iron_serving') or nutr.get('iron_100g'), 'mg') or 'N/A',
                'potassium': fmt(nutr.get('potassium_serving') or nutr.get('potassium_100g'), 'mg') or 'N/A',
                'serving_size': product.get('serving_size') or '100g'
            }
        }
        return resp

    try:
        data = request.get_json()
        query = (data.get('query') or '').strip()
        qtype = data.get('type') or 'manual'
        if not query:
            return jsonify({'success': False, 'message': 'Query is required'})

        matched_product = None

        # 1) Try OpenFoodFacts by barcode or name for exact data
        if qtype == 'barcode' and query.isdigit():
            prod = off_by_barcode(query)
            if prod:
                matched_product = map_off_to_response(prod)
        if not matched_product and qtype != 'barcode':
            prod = off_search_by_name(query)
            if prod:
                matched_product = map_off_to_response(prod)

        # 2) Fallback to Azure OpenAI for structured estimate
        if not matched_product:
            system_prompt = (
                "You are a professional nutritionist and food scientist. Provide accurate, detailed nutritional information for food products. "
                "Return ONLY valid JSON with precise nutritional facts. Be specific about the food item - if someone asks for 'rice', provide data for plain white rice, not rice cakes or processed rice products. "
                "Use standard serving sizes (100g for most foods, 1 cup for liquids, 1 medium piece for fruits). "
                "Fields: product_name (be specific about the exact food), nutrition_facts with calories (include serving size), total_fat, saturated_fat, cholesterol, "
                "sodium, total_carbohydrates, dietary_fiber, sugars, protein, vitamin_c, calcium, iron, potassium, serving_size. "
                "Provide realistic, scientifically accurate values. If unsure about specific values, use 'N/A' rather than guessing."
            )
            user_prompt = f"Provide detailed nutritional facts for: {query}. Be specific about the exact food item and provide accurate nutritional data per 100g serving."
            payload = {
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                "temperature": 0.1,
                "top_p": 0.95,
                "max_tokens": 600
            }
            url = f"{AZURE_OAI_ENDPOINT}openai/deployments/{AZURE_OAI_DEPLOYMENT}/chat/completions?api-version={AZURE_OAI_API_VERSION}"
            headers = {"Content-Type": "application/json", "api-key": AZURE_OAI_KEY}
            resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
            if resp.status_code >= 400:
                raise Exception(f"Azure OpenAI HTTP {resp.status_code}: {resp.text[:200]}")
            ai_data = resp.json()
            ai_response = ai_data.get("choices", [{}])[0].get("message", {}).get("content", "{}").strip()
            # Extract JSON
            m = re.search(r'\{[\s\S]*\}', ai_response)
            if m:
                matched_product = json.loads(m.group(0))
            else:
                matched_product = {
                    'product_name': query.title(),
                    'nutrition_facts': {
                        'calories': 'N/A',
                        'total_fat': 'N/A',
                        'saturated_fat': 'N/A',
                        'cholesterol': 'N/A',
                        'sodium': 'N/A',
                        'total_carbohydrates': 'N/A',
                        'dietary_fiber': 'N/A',
                        'sugars': 'N/A',
                        'protein': 'N/A',
                        'vitamin_c': 'N/A',
                        'calcium': 'N/A',
                        'iron': 'N/A',
                        'potassium': 'N/A',
                        'serving_size': 'N/A'
                    }
                }

        return jsonify({'success': True, 'data': matched_product})

    except Exception as e:
        return jsonify({'success': False, 'message': f'Error analyzing nutrition: {str(e)}'})

@app.route('/get-recipe/<int:item_id>', methods=['GET'])
def get_recipe(item_id):
    try:
        # Get the food item
        food_item = FoodItem.query.get_or_404(item_id)
        
        # Search for recipes using the food item name
        results = search_client.search(
            search_text=food_item.name,
            query_type=QueryType.SIMPLE,
            include_total_count=True,
            top=3  # Limit to 3 recipes
        )
        
        recipes = []
        for result in results:
            recipes.append({
                'title': result['title'],
                'ingredients': result['ingredients'],
                'instructions': result['instructions'],
                'image_url': result.get('image_url', '')
            })
        
        return jsonify({
            'success': True,
            'recipes': recipes,
            'item_id': item_id
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f"Error retrieving recipes: {str(e)}"
        })

@app.route('/find-donations', methods=['POST'])
@login_required
def find_donations():
    try:
        data = request.get_json()
        city = data.get('city', '').strip()
        
        if not city:
            return jsonify({"success": False, "message": "City name is required"}), 400
        
        # Use Azure OpenAI to find nearby charitable organizations
        organizations = find_nearby_organizations(city)
        
        return jsonify({
            "success": True,
            "organizations": organizations
        })
        
    except Exception as e:
        app.logger.error(f"Error finding donations: {str(e)}")
        return jsonify({
            "success": False,
            "message": f"Error finding organizations: {str(e)}"
        }), 500

def find_nearby_organizations(city):
    """Use Azure OpenAI to find nearby charitable organizations"""
    try:
        # Prepare the prompt for Azure OpenAI
        prompt = f"""
        Find 5-8 real charitable organizations in {city}, India that accept food donations. 
        Include NGOs, orphanages, old age homes, and food banks.
        
        For each organization, provide:
        - Name
        - Type (NGO/Orphanage/Old Age Home/Food Bank)
        - Address (specific address in {city})
        - Phone number (if available)
        - Email (if available)
        - Website (if available)
        - Brief description of their work
        
        Format the response as a JSON array with this structure:
        [
            {{
                "name": "Organization Name",
                "type": "NGO/Orphanage/Old Age Home/Food Bank",
                "address": "Full address in {city}",
                "phone": "Phone number or null",
                "email": "Email or null",
                "website": "Website URL or null",
                "description": "Brief description of their work and food donation needs"
            }}
        ]
        
        Make sure all organizations are real and located in {city}. Include well-known organizations 
        like Akshaya Patra, Goonj, Robin Hood Army, etc. if they have presence in {city}.
        """
        
        # Call Azure OpenAI
        headers = {
            'Content-Type': 'application/json',
            'api-key': AZURE_OAI_KEY
        }
        
        payload = {
            "messages": [
                {
                    "role": "system",
                    "content": "You are a helpful assistant that provides accurate information about charitable organizations in India. Always respond with valid JSON format."
                },
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "max_tokens": 2000,
            "temperature": 0.3
        }
        
        response = requests.post(
            f"{AZURE_OAI_ENDPOINT}/openai/deployments/{AZURE_OAI_DEPLOYMENT}/chat/completions?api-version={AZURE_OAI_API_VERSION}",
            headers=headers,
            json=payload,
            timeout=30
        )
        
        if response.status_code == 200:
            result = response.json()
            content = result['choices'][0]['message']['content'].strip()
            
            # Try to parse JSON response
            try:
                # Clean the response to extract JSON
                if content.startswith('```json'):
                    content = content[7:-3]
                elif content.startswith('```'):
                    content = content[3:-3]
                
                organizations = json.loads(content)
                
                # Validate and clean the data
                if isinstance(organizations, list):
                    cleaned_orgs = []
                    for org in organizations:
                        if isinstance(org, dict) and 'name' in org:
                            cleaned_org = {
                                'name': org.get('name', 'Unknown Organization'),
                                'type': org.get('type', 'Charitable Organization'),
                                'address': org.get('address', f'Address not available in {city}'),
                                'phone': org.get('phone'),
                                'email': org.get('email'),
                                'website': org.get('website'),
                                'description': org.get('description', 'Accepts food donations to help those in need.')
                            }
                            cleaned_orgs.append(cleaned_org)
                    
                    return cleaned_orgs[:8]  # Limit to 8 organizations
                
            except json.JSONDecodeError:
                # If JSON parsing fails, create a fallback response
                return create_fallback_organizations(city)
        
        # If API call fails, return fallback organizations
        return create_fallback_organizations(city)
        
    except Exception as e:
        app.logger.error(f"Error in find_nearby_organizations: {str(e)}")
        return create_fallback_organizations(city)

def create_fallback_organizations(city):
    """Create fallback organizations when API fails"""
    fallback_orgs = [
        {
            'name': 'Akshaya Patra Foundation',
            'type': 'NGO',
            'address': f'Multiple locations in {city} - Contact for nearest center',
            'phone': '080-30143400',
            'email': 'info@akshayapatra.org',
            'website': 'https://www.akshayapatra.org',
            'description': 'Provides mid-day meals to school children. Accepts food donations and volunteers.'
        },
        {
            'name': 'Robin Hood Army',
            'type': 'NGO',
            'address': f'Various locations in {city}',
            'phone': None,
            'email': 'contact@robinhoodarmy.com',
            'website': 'https://robinhoodarmy.com',
            'description': 'Volunteer-based organization that serves surplus food to the less fortunate.'
        },
        {
            'name': 'Goonj',
            'type': 'NGO',
            'address': f'Multiple centers in {city}',
            'phone': '011-26972351',
            'email': 'mail@goonj.org',
            'website': 'https://goonj.org',
            'description': 'Works on various social causes including food distribution to underprivileged communities.'
        },
        {
            'name': f'Local Orphanage - {city}',
            'type': 'Orphanage',
            'address': f'Contact local authorities for orphanages in {city}',
            'phone': None,
            'email': None,
            'website': None,
            'description': 'Local orphanages often accept food donations. Contact local child welfare department for specific addresses.'
        },
        {
            'name': f'Old Age Home - {city}',
            'type': 'Old Age Home',
            'address': f'Contact local authorities for old age homes in {city}',
            'phone': None,
            'email': None,
            'website': None,
            'description': 'Local old age homes welcome food donations. Contact local senior citizen welfare department for specific addresses.'
        }
    ]
    
    return fallback_orgs

@app.route('/chat', methods=['POST'])
@login_required
def chat():
    try:
        data = request.get_json(silent=True) or {}
        user_message = data.get('message', '').strip()
        if not user_message:
            return jsonify({"success": False, "message": "Message is required"}), 400

        # Build compact context from saved items for current user
        items = FoodItem.query.filter_by(user_id=session['user_id']).order_by(FoodItem.parsed_date).limit(20).all()
        items_lines = []
        for item in items:
            items_lines.append(
                f"- id:{item.id} name:{item.name} expiry:{item.expiry_date} parsed:{item.parsed_date.strftime('%Y-%m-%d')} days_left:{(item.parsed_date - datetime.now().date()).days}"
            )
        saved_context = "\n".join(items_lines) if items_lines else "(no saved items)"

        system_prompt = (
            "You are a helpful food assistant for a Food Expiry Tracker app. "
            "Answer user questions about food safety, storage, recipes, and general food topics. "
            "You also have access to a snapshot of the user's saved food items. If the question references their saved items, "
            "use the provided snapshot to answer. If needed, cite item names and days left. Be concise and accurate."
        )

        context_block = f"Saved items snapshot:\n{saved_context}"

        payload = {
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"{context_block}\n\nUser question: {user_message}"}
            ],
            "temperature": 0.3,
            "top_p": 0.95,
            "max_tokens": 500
        }

        url = f"{AZURE_OAI_ENDPOINT}openai/deployments/{AZURE_OAI_DEPLOYMENT}/chat/completions?api-version={AZURE_OAI_API_VERSION}"
        headers = {
            "Content-Type": "application/json",
            "api-key": AZURE_OAI_KEY
        }

        resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=30)
        if resp.status_code >= 400:
            return jsonify({
                "success": False,
                "message": f"Upstream error: {resp.status_code} {resp.text[:200]}"
            }), 502

        data = resp.json()
        answer = data.get("choices", [{}])[0].get("message", {}).get("content", "Sorry, I couldn't generate a response.")
        return jsonify({"success": True, "answer": answer})
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

if __name__ == '__main__':
    # Start background notification worker when running the app directly
    start_notification_worker()
    app.run(debug=True)