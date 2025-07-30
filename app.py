from flask import Flask, render_template, redirect, url_for, request, make_response, jsonify, session, send_file
from models import db, User, UserPrivacyPreferences, DataProcessingLog, DataExportRequest
from datetime import datetime, timezone, timedelta
import secrets
import requests
import os
import json
import zipfile
import tempfile
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from dotenv import load_dotenv
from flask_migrate import Migrate
from functools import wraps
from pymongo import MongoClient
from bson.objectid import ObjectId

# Load environment variables
load_dotenv()


# Initialize Flask app
app = Flask(__name__)
migrate = Migrate(app, db)


# MongoDB setup
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/tickvote')
mongo_client = MongoClient(MONGO_URI)
mongo_db = mongo_client.get_default_database()
polls_collection = mongo_db['polls']
options_collection = mongo_db['options']
privacy_collection = mongo_db['privacy_preferences']

# Configuration constants
class Config:
    # Security settings
    SECRET_KEY = os.getenv('FLASK_SECRET_KEY', 'changeme')
    
    # Database settings
    DATABASE_URI = os.getenv('DATABASE_URL', 'sqlite:///../instance/tickvote.db')
    
    # reCAPTCHA settings
    RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')
    RECAPTCHA_SITE_KEY = os.getenv('RECAPTCHA_SITE_KEY', '')
    
    # Admin settings
    ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme')
    ADMIN_FIREBASE_UID = os.getenv('ADMIN_FIREBASE_UID')
    
    # Firebase settings
    FIREBASE_CRED_PATH = os.getenv('FIREBASE_CRED_PATH', 'firebase_service_account.json')
    
    # Session configuration
    SESSION_COOKIE_SECURE = os.getenv('SESSION_SECURE', 'False').lower() == 'true'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    PERMANENT_SESSION_LIFETIME = timedelta(days=365)
    
    # App settings
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    PORT = int(os.getenv('PORT', 8080))
    
    @classmethod
    def validate(cls):
        """Validate configuration and warn about insecure defaults"""
        warnings = []
        
        if cls.SECRET_KEY == 'changeme':
            warnings.append("SECRET_KEY is using default value. Please set FLASK_SECRET_KEY environment variable.")
        
        if cls.ADMIN_PASSWORD == 'changeme':
            warnings.append("ADMIN_PASSWORD is using default value. Please set ADMIN_PASSWORD environment variable.")
        
        if not cls.ADMIN_FIREBASE_UID:
            warnings.append("ADMIN_FIREBASE_UID not set. Admin access via Firebase will be disabled.")
        
        for warning in warnings:
            print(f"Configuration Warning: {warning}")
        
        return len(warnings) == 0

# Apply configuration
app.config.update({
    'SECRET_KEY': Config.SECRET_KEY,
    'SQLALCHEMY_DATABASE_URI': Config.DATABASE_URI,
    'SQLALCHEMY_TRACK_MODIFICATIONS': False,
    'SESSION_COOKIE_SECURE': Config.SESSION_COOKIE_SECURE,
    'SESSION_COOKIE_HTTPONLY': Config.SESSION_COOKIE_HTTPONLY,
    'SESSION_COOKIE_SAMESITE': Config.SESSION_COOKIE_SAMESITE,
    'PERMANENT_SESSION_LIFETIME': Config.PERMANENT_SESSION_LIFETIME
})

# Validate configuration
Config.validate()

db.init_app(app)

# Initialize Firebase
if os.path.exists(Config.FIREBASE_CRED_PATH):
    if not firebase_admin._apps:
        cred = credentials.Certificate(Config.FIREBASE_CRED_PATH)
        firebase_admin.initialize_app(cred)
else:
    # Try to find the .json file with a double extension (common mistake)
    alt_path = Config.FIREBASE_CRED_PATH + '.json'
    if os.path.exists(alt_path):
        if not firebase_admin._apps:
            cred = credentials.Certificate(alt_path)
            firebase_admin.initialize_app(cred)
    else:
        print(f"Warning: Firebase service account file '{Config.FIREBASE_CRED_PATH}' not found. Firebase features will be disabled.")

def generate_token():
    return secrets.token_urlsafe(8)

def get_owner_tokens():
    tokens = request.cookies.get('owner_tokens')
    if tokens:
        return set(tokens.split(','))
    return set()

def add_owner_token_cookie(response, owner_token):
    tokens = get_owner_tokens()
    tokens.add(owner_token)
    response.set_cookie('owner_tokens', ','.join(tokens), max_age=60*60*24*365)
    return response

def get_voted_tokens():
    tokens = request.cookies.get('voted_tokens')
    if tokens:
        return set(tokens.split(','))
    return set()

def add_voted_token_cookie(response, poll_token):
    tokens = get_voted_tokens()
    tokens.add(poll_token)
    response.set_cookie('voted_tokens', ','.join(tokens), max_age=60*60*24*365)
    return response

def verify_recaptcha(response_token):
    if not Config.RECAPTCHA_SECRET_KEY:
        return True  # Skip verification if no key is configured
    payload = {
        'secret': Config.RECAPTCHA_SECRET_KEY,
        'response': response_token
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = r.json()
    return result.get('success', False)

def is_email_verified(firebase_uid):
    """Check if a Firebase user's email is verified"""
    try:
        if firebase_uid == Config.ADMIN_FIREBASE_UID:
            return True  # Admin bypass
        user_record = firebase_auth.get_user(firebase_uid)
        return user_record.email_verified
    except Exception as e:
        print(f"Error checking email verification: {e}")
        return False

def require_email_verification(f):
    """Decorator to require email verification for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        firebase_uid = get_firebase_uid()
        if firebase_uid and not is_email_verified(firebase_uid):
            try:
                user_record = firebase_auth.get_user(firebase_uid)
                return redirect(url_for('verify_email', email=user_record.email))
            except:
                return redirect(url_for('verify_email'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
def index():
    firebase_uid = get_firebase_uid()
    user_name = None
    if firebase_uid:
        user_name = get_user_display_name(firebase_uid)
    
    return render_template('index.html', firebase_uid=firebase_uid, user_name=user_name)

@app.route('/login/firebase', methods=['POST'])
def firebase_login():
    try:
        id_token = request.json.get('idToken')
        if not id_token:
            return jsonify({'success': False, 'error': 'No ID token provided'}), 400
        
        print(f"Attempting to verify Firebase ID token...")
        decoded_token = firebase_auth. verify_id_token(id_token)
        print(f"Firebase token verified successfully for UID: {decoded_token['uid']}")
        
        # Get the user record to check email verification
        user_record = firebase_auth.get_user(decoded_token['uid'])
        
        # Check if email is verified (allow admin to bypass verification)
        if not user_record.email_verified and decoded_token['uid'] != Config.ADMIN_FIREBASE_UID:
            print(f"Email not verified for user: {user_record.email}")
            return jsonify({
                'success': False,
                'error': 'email_not_verified',
                'redirect_url': '/verify-email',
                'email': user_record.email
            }), 401
        
        session['firebase_uid'] = decoded_token['uid']
        session.permanent = True  # Make session permanent
        
        # Claim any anonymous polls for this user
        claimed_polls = claim_anonymous_polls(decoded_token['uid'])
        
        return jsonify({
            'success': True, 
            'claimed_polls': claimed_polls,
            'redirect_url': '/logged_in'
        })
    except Exception as e:
        print(f"Firebase login error: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 401

@app.route('/logout')
@app.route('/logout/firebase')
def logout():
    """Handle logout for both Firebase and admin sessions"""
    session.pop('firebase_uid', None)
    session.pop('admin_logged_in', None)
    return redirect(url_for('index'))

@app.route('/logged_in')
@require_email_verification
def logged_in():
    firebase_uid = get_firebase_uid()
    if not firebase_uid:
        return redirect(url_for('login'))
    
    # Get the claimed polls count from query parameter if available
    claimed_polls = request.args.get('claimed_polls', 0, type=int)
    
    return render_template('logged_in.html', 
                         firebase_uid=firebase_uid, 
                         claimed_polls=claimed_polls)

def get_firebase_uid():
    return session.get('firebase_uid')

def is_admin(firebase_uid=None):
    """Check if the current user is an admin"""
    if session.get('admin_logged_in'):
        return True
    
    if firebase_uid is None:
        firebase_uid = get_firebase_uid()
    
    return firebase_uid and firebase_uid == Config.ADMIN_FIREBASE_UID

def get_user_display_name(firebase_uid):
    """Get display name for a Firebase user"""
    try:
        user_record = firebase_auth.get_user(firebase_uid)
        return user_record.display_name or user_record.email or "User"
    except Exception as e:
        print(f"Error getting user info: {e}")
        return "User"

def claim_anonymous_polls(firebase_uid):
    """
    Claim all polls that were created with owner tokens stored in cookies
    and assign them to the logged-in Firebase user
    """
    try:
        owner_tokens = get_owner_tokens()
        if not owner_tokens:
            return 0
        
        # Find polls that match the owner tokens and don't have a firebase_uid yet
        polls_to_claim = Poll.query.filter(
            Poll.owner_token.in_(owner_tokens),
            Poll.firebase_uid.is_(None)
        ).all()
        
        claimed_count = 0
        for poll in polls_to_claim:
            poll.firebase_uid = firebase_uid
            claimed_count += 1
        
        if claimed_count > 0:
            db.session.commit()
            print(f"Claimed {claimed_count} polls for Firebase user {firebase_uid}")
        
        return claimed_count
    except Exception as e:
        print(f"Error claiming polls: {e}")
        db.session.rollback()
        return 0
@app.route('/create', methods=['GET', 'POST'])
def create_poll():
    firebase_uid = get_firebase_uid()
    if request.method == 'POST':
        question = request.form.get('question', '').strip()
        options = [opt.strip() for opt in request.form.getlist('options') if opt.strip()]
        expiry_hours = request.form.get('expiry')
        # Validation
        if not question:
            return render_template('create_poll.html', error="Please provide a question.")
        if not options or len(options) < 1:
            return render_template('create_poll.html', error="Please provide at least one option.")
        try:
            expiry_hours = int(expiry_hours)
            if expiry_hours < 1 or expiry_hours > 168:
                raise ValueError()
        except (ValueError, TypeError):
            return render_template('create_poll.html', error="Expiry must be between 1 and 168 hours.")
        try:
            poll_token = generate_token()
            stats_token = generate_token()
            owner_token = generate_token()
            expiry_time = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
            poll_doc = {
                'question': question,
                'token': poll_token,
                'stats_token': stats_token,
                'owner_token': owner_token,
                'expires_at': expiry_time,
                'firebase_uid': firebase_uid,
                'paused': False,
                'locked': False,
            }
            poll_result = polls_collection.insert_one(poll_doc)
            poll_id = poll_result.inserted_id
            for opt_text in options:
                options_collection.insert_one({
                    'poll_id': poll_id,
                    'text': opt_text,
                    'votes': 0
                })
            poll_url = url_for('view_poll_token', token=poll_token, _external=True)
            stats_url = url_for('poll_stats', stats_token=stats_token, _external=True)
            resp = make_response(render_template('poll_created.html', 
                                               poll_url=poll_url, 
                                               stats_url=stats_url, 
                                               expiry=expiry_time))
            resp = add_owner_token_cookie(resp, owner_token)
            return resp
        except Exception as e:
            print(f"Error creating poll: {e}")
            return render_template('create_poll.html', error="An error occurred while creating the poll. Please try again.")
    return render_template('create_poll.html')

@app.route('/dashboard')
@require_email_verification
def dashboard():
    try:
        firebase_uid = get_firebase_uid()
        tokens = get_owner_tokens()
        polls = []
        # Get Firebase user polls
        if firebase_uid:
            firebase_polls = list(polls_collection.find({'firebase_uid': firebase_uid}))
            polls.extend(firebase_polls)
        # Get anonymous user polls via cookies
        if tokens:
            token_polls = list(polls_collection.find({'owner_token': {'$in': list(tokens)}}))
            polls.extend(token_polls)
        # Remove duplicates by _id
        seen_ids = set()
        unique_polls = []
        for poll in polls:
            poll_id = str(poll['_id'])
            if poll_id not in seen_ids:
                unique_polls.append(poll)
                seen_ids.add(poll_id)
        show_login_prompt = not unique_polls and not firebase_uid and not tokens
        # Attach options to each poll for template compatibility
        for poll in unique_polls:
            poll['options'] = list(options_collection.find({'poll_id': poll['_id']}))
        return render_template('dashboard.html', 
                             polls=unique_polls, 
                             show_login_prompt=show_login_prompt)
    except Exception as e:
        print(f"Error in dashboard: {e}")
        return render_template('dashboard.html', 
                             polls=[], 
                             error="Error loading dashboard")

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect to dashboard
    if get_firebase_uid():
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    # If user is already logged in, redirect to dashboard
    if get_firebase_uid():
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/reset-password')
def reset_password():
    # If user is already logged in, redirect to dashboard
    if get_firebase_uid():
        return redirect(url_for('dashboard'))
    return render_template('reset_password.html')

@app.route('/account-disabled')
def account_disabled():
    # This route can be accessed by anyone
    return render_template('account_disabled.html')

@app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
def view_poll(poll_id):
    poll = polls_collection.find_one({'_id': ObjectId(poll_id)})
    if not poll:
        return render_template('404.html'), 404
    expires_at = poll.get('expires_at')
    # Ensure expires_at is timezone-aware (UTC)
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    expired = expires_at and expires_at < datetime.now(timezone.utc)
    paused = poll.get('paused', False)
    locked = poll.get('locked', False)
    voted_tokens = get_voted_tokens()
    already_voted = poll['token'] in voted_tokens
    can_vote = not (expired or paused or locked or already_voted)
    options = list(options_collection.find({'poll_id': poll['_id']}))
    if request.method == 'POST' and can_vote:
        option_id = request.form.get('option')
        option = options_collection.find_one({'_id': ObjectId(option_id), 'poll_id': poll['_id']})
        if option:
            options_collection.update_one({'_id': ObjectId(option_id)}, {'$inc': {'votes': 1}})
        resp = make_response(redirect(url_for('view_poll', poll_id=poll_id)))
        return add_voted_token_cookie(resp, poll['token'])
    return render_template('poll.html', poll=poll, options=options, expired=expired, paused=paused, locked=locked, already_voted=already_voted)

@app.route('/poll/token/<token>', methods=['GET', 'POST'])
def view_poll_token(token):
    poll = polls_collection.find_one({'token': token})
    if not poll:
        return render_template('404.html'), 404
    expires_at = poll.get('expires_at')
    # Ensure expires_at is timezone-aware (UTC)
    if expires_at and expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    expired = expires_at and expires_at < datetime.now(timezone.utc)
    paused = poll.get('paused', False)
    locked = poll.get('locked', False)
    voted_tokens = get_voted_tokens()
    already_voted = poll['token'] in voted_tokens
    just_voted = False
    can_vote = not (expired or paused or locked or already_voted)
    options = list(options_collection.find({'poll_id': poll['_id']}))
    # For template compatibility, set poll.options and ensure _id is string for form value
    for opt in options:
        if '_id' in opt:
            opt['id'] = str(opt['_id'])
    poll['options'] = options
    if request.method == 'POST':
        if can_vote:
            option_id = request.form.get('option')
            if not option_id:
                return render_template('poll.html', poll=poll, expired=expired, paused=paused, locked=locked, already_voted=already_voted, error="No option selected.")
            try:
                option_obj_id = ObjectId(option_id)
            except Exception:
                return render_template('poll.html', poll=poll, expired=expired, paused=paused, locked=locked, already_voted=already_voted, error="Invalid option selected.")
            option = options_collection.find_one({'_id': option_obj_id, 'poll_id': poll['_id']})
            if option:
                options_collection.update_one({'_id': option_obj_id}, {'$inc': {'votes': 1}})
            resp = make_response(redirect(url_for('view_poll_token', token=token, voted='1')))
            return add_voted_token_cookie(resp, poll['token'])
        else:
            return render_template('poll.html', poll=poll, expired=expired, paused=paused, locked=locked, already_voted=already_voted, tried_to_vote_again=True)
    just_voted = request.args.get('voted') == '1'
    return render_template('poll.html', poll=poll, expired=expired, paused=paused, locked=locked, already_voted=already_voted, just_voted=just_voted)

@app.route('/poll/token/<token>/pause', methods=['POST'])
def pause_poll(token):
    poll = Poll.query.filter_by(token=token).first_or_404()
    poll.paused = True
    db.session.commit()
    return redirect(url_for('poll_stats', stats_token=poll.stats_token))

@app.route('/poll/token/<token>/unpause', methods=['POST'])
def unpause_poll(token):
    poll = Poll.query.filter_by(token=token).first_or_404()
    poll.paused = False
    db.session.commit()
    return redirect(url_for('poll_stats', stats_token=poll.stats_token))

@app.route('/admin/login', methods=['GET', 'POST'])
def admin_login():
    error = None
    firebase_uid = get_firebase_uid()
    
    # If user is already an admin via Firebase, redirect to dashboard
    if is_admin(firebase_uid):
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        password = request.form.get('password')
        if password == Config.ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Incorrect password."
    
    return render_template('admin_login.html', 
                         error=error, 
                         firebase_uid=firebase_uid, 
                         admin_firebase_uid=Config.ADMIN_FIREBASE_UID)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_admin():
            return redirect(url_for('admin_login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/admin')
@admin_required
def admin_dashboard():
    polls = list(polls_collection.find())
    for poll in polls:
        poll['options'] = list(options_collection.find({'poll_id': poll['_id']}))
    return render_template('admin_dashboard.html', polls=polls)


# Accept poll_id as string for MongoDB ObjectId
@app.route('/admin/poll/<poll_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_poll(poll_id):
    try:
        obj_id = ObjectId(poll_id)
    except Exception:
        return redirect(url_for('admin_dashboard'))
    poll = polls_collection.find_one({'_id': obj_id})
    if not poll:
        return redirect(url_for('admin_dashboard'))
    poll['options'] = list(options_collection.find({'poll_id': obj_id}))
    if request.method == 'POST':
        question = request.form.get('question')
        if question:
            polls_collection.update_one({'_id': obj_id}, {'$set': {'question': question}})
        for option in poll['options']:
            new_text = request.form.get(f'option_text_{option["_id"]}')
            if new_text:
                options_collection.update_one({'_id': option['_id']}, {'$set': {'text': new_text}})
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit_poll.html', poll=poll)


# Accept poll_id as string for MongoDB ObjectId
@app.route('/admin/poll/<poll_id>/delete', methods=['POST'])
@admin_required
def admin_delete_poll(poll_id):
    try:
        obj_id = ObjectId(poll_id)
    except Exception:
        return redirect(url_for('admin_dashboard'))
    options_collection.delete_many({'poll_id': obj_id})
    polls_collection.delete_one({'_id': obj_id})
    return redirect(url_for('admin_dashboard'))


# Accept poll_id as string for MongoDB ObjectId
@app.route('/admin/poll/<poll_id>/lock', methods=['POST'])
@admin_required
def admin_lock_poll(poll_id):
    try:
        obj_id = ObjectId(poll_id)
    except Exception:
        return redirect(url_for('admin_dashboard'))
    polls_collection.update_one({'_id': obj_id}, {'$set': {'locked': True}})
    return redirect(url_for('admin_dashboard'))


# Accept poll_id as string for MongoDB ObjectId
@app.route('/admin/poll/<poll_id>/unlock', methods=['POST'])
@admin_required
def admin_unlock_poll(poll_id):
    try:
        obj_id = ObjectId(poll_id)
    except Exception:
        return redirect(url_for('admin_dashboard'))
    polls_collection.update_one({'_id': obj_id}, {'$set': {'locked': False}})
    return redirect(url_for('admin_dashboard'))


# Accept option_id as string for MongoDB ObjectId
@app.route('/admin/option/<option_id>/add_vote', methods=['POST'])
@admin_required
def admin_add_vote(option_id):
    try:
        obj_id = ObjectId(option_id)
    except Exception:
        return redirect(request.referrer or url_for('admin_dashboard'))
    option = options_collection.find_one({'_id': obj_id})
    if option:
        options_collection.update_one({'_id': obj_id}, {'$inc': {'votes': 1}})
    return redirect(request.referrer or url_for('admin_dashboard'))


# Accept option_id as string for MongoDB ObjectId
@app.route('/admin/option/<option_id>/remove_vote', methods=['POST'])
@admin_required
def admin_remove_vote(option_id):
    try:
        obj_id = ObjectId(option_id)
    except Exception:
        return redirect(request.referrer or url_for('admin_dashboard'))
    option = options_collection.find_one({'_id': obj_id})
    if option and option.get('votes', 0) > 0:
        options_collection.update_one({'_id': obj_id}, {'$inc': {'votes': -1}})
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/stats/<stats_token>', methods=['GET', 'POST'])
def poll_stats(stats_token):
    poll = polls_collection.find_one({'stats_token': stats_token})
    if not poll:
        return render_template('404.html'), 404
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            options_collection.delete_many({'poll_id': poll['_id']})
            polls_collection.delete_one({'_id': poll['_id']})
            return render_template('poll_deleted.html')
        elif action == 'pause':
            polls_collection.update_one({'_id': poll['_id']}, {'$set': {'paused': True}})
        elif action == 'unpause':
            polls_collection.update_one({'_id': poll['_id']}, {'$set': {'paused': False}})
    poll['options'] = list(options_collection.find({'poll_id': poll['_id']}))
    return render_template('poll_stats.html', poll=poll)

@app.context_processor
def inject_recaptcha_site_key():
    return dict(RECAPTCHA_SITE_KEY=Config.RECAPTCHA_SITE_KEY)

@app.route('/about')
def about():
    return render_template('about.html')

@app.errorhandler(404)
def error_four_oh_four(s):
    return render_template('404.html')

@app.route('/verify-email')
def verify_email():
    """Email verification page"""
    # This page can be accessed by anyone, but typically reached after signup
    user_email = request.args.get('email', 'your-email@example.com')
    return render_template('verify_email.html', user_email=user_email)

@app.route('/verify-recaptcha', methods=['POST'])
def verify_recaptcha_endpoint():
    """Verify reCAPTCHA response on the server side"""
    try:
        data = request.get_json()
        recaptcha_response = data.get('recaptchaResponse')
        
        if not recaptcha_response:
            return jsonify({'success': False, 'error': 'No reCAPTCHA response provided'}), 400
        
        # Verify the reCAPTCHA response
        is_valid = verify_recaptcha(recaptcha_response)
        
        if is_valid:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'reCAPTCHA verification failed'}), 400
            
    except Exception as e:
        print(f"reCAPTCHA verification error: {e}")
        return jsonify({'success': False, 'error': 'Server error during verification'}), 500

@app.route('/gdpr/request-data', methods=['GET', 'POST'])
def request_data():
    """Request personal data export under GDPR"""
    if request.method == 'POST':
        firebase_uid = get_firebase_uid()
        if not firebase_uid:
            return jsonify({'success': False, 'error': 'User not authenticated'}), 401
        
        # Log the data request
        log_entry = DataProcessingLog(
            firebase_uid=firebase_uid,
            action='data_export_requested',
            timestamp=datetime.now(timezone.utc)
        )
        db.session.add(log_entry)
        db.session.commit()
        
        # Create a ZIP file of the user's data
        try:
            with tempfile.TemporaryDirectory() as tmpdirname:
                zip_path = os.path.join(tmpdirname, 'user_data.zip')
                with zipfile.ZipFile(zip_path, 'w') as zipf:
                    # Add user info
                    user = User.query.filter_by(firebase_uid=firebase_uid).first()
                    if user:
                        user_info = {
                            'firebase_uid': user.firebase_uid,
                            'email': user.email,
                            'display_name': user.display_name,
                            'photo_url': user.photo_url
                        }
                        zipf.writestr('user_info.json', json.dumps(user_info))
                    
                    # Add privacy preferences
                    preferences = UserPrivacyPreferences.query.filter_by(firebase_uid=firebase_uid).all()
                    prefs_dict = {pref.category: pref.value for pref in preferences}
                    zipf.writestr('privacy_preferences.json', json.dumps(prefs_dict))
                    
                    # Add polls and options
                    polls = Poll.query.filter_by(firebase_uid=firebase_uid).all()
                    for poll in polls:
                        poll_data = {
                            'id': poll.id,
                            'question': poll.question,
                            'token': poll.token,
                            'expires_at': poll.expires_at.isoformat() if poll.expires_at else None,
                            'options': [{'id': opt.id, 'text': opt.text, 'votes': opt.votes} for opt in poll.options]
                        }
                        zipf.writestr(f'polls/poll_{poll.id}.json', json.dumps(poll_data))
                
                # Send the ZIP file to the user
                return send_file(zip_path, as_attachment=True, download_name='user_data.zip')
        
        except Exception as e:
            print(f"Error creating data export: {e}")
            return jsonify({'success': False, 'error': 'Error creating data export'}), 500
    
    return render_template('request_data.html')

@app.route('/gdpr/erase-data', methods=['POST'])
def erase_data():
    """Handle GDPR data erasure requests"""
    firebase_uid = get_firebase_uid()
    if not firebase_uid:
        return jsonify({'success': False, 'error': 'User not authenticated'}), 401
    
    # Log the data erasure request
    log_entry = DataProcessingLog(
        firebase_uid=firebase_uid,
        action='data_eraser_requested',
        timestamp=datetime.now(timezone.utc)
    )
    db.session.add(log_entry)
    db.session.commit()
    
    # Erase user data
    try:
        # Delete user from Firebase Auth
        firebase_auth.delete_user(firebase_uid)
        
        # Delete user data from database
        User.query.filter_by(firebase_uid=firebase_uid).delete()
        UserPrivacyPreferences.query.filter_by(firebase_uid=firebase_uid).delete()
        Poll.query.filter_by(firebase_uid=firebase_uid).delete()
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        print(f"Error erasing data: {e}")
        return jsonify({'success': False, 'error': 'Error erasing data'}), 500

# GDPR Helper Functions
def log_data_processing(firebase_uid, action, legal_basis, data_categories, purpose):
    """Log data processing activities for GDPR compliance"""
    try:
        log_entry = DataProcessingLog(
            firebase_uid=firebase_uid,
            action=action,
            legal_basis=legal_basis,
            data_categories=json.dumps(data_categories),
            purpose=purpose,
            ip_address=request.environ.get('HTTP_X_FORWARDED_FOR', request.environ.get('REMOTE_ADDR')),
            user_agent=request.environ.get('HTTP_USER_AGENT', '')
        )
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        print(f"Error logging data processing: {e}")


# MongoDB version of get_user_privacy_preferences
def get_user_privacy_preferences(firebase_uid):
    """Get user's privacy preferences from MongoDB, create default if not exists"""
    if not firebase_uid:
        return None
    prefs = privacy_collection.find_one({'firebase_uid': firebase_uid})
    if not prefs:
        # Create default preferences
        prefs = {
            'firebase_uid': firebase_uid,
            'functional_cookies': True,
            'analytics_cookies': False,
            'auto_delete_polls': False,
            'email_notifications': True,
            'data_retention_days': 365,
            'consent_given_at': datetime.utcnow(),
            'consent_updated_at': datetime.utcnow(),
            'created_at': datetime.utcnow(),
            'updated_at': datetime.utcnow(),
        }
        privacy_collection.insert_one(prefs)
    return privacy_collection.find_one({'firebase_uid': firebase_uid})

def export_user_data(firebase_uid):
    """Export all user data for GDPR data portability"""
    try:
        # Get user info from Firebase
        user_record = firebase_auth.get_user(firebase_uid)
        
        # Get polls created by user
        polls = Poll.query.filter_by(firebase_uid=firebase_uid).all()
        
        # Get privacy preferences
        preferences = get_user_privacy_preferences(firebase_uid)
        
        # Get data processing logs
        logs = DataProcessingLog.query.filter_by(firebase_uid=firebase_uid).all()
        
        export_data = {
            'user_info': {
                'firebase_uid': firebase_uid,
                'email': user_record.email if hasattr(user_record, 'email') else None,
                'display_name': user_record.display_name if hasattr(user_record, 'display_name') else None,
                'email_verified': user_record.email_verified if hasattr(user_record, 'email_verified') else False,
                'creation_time': user_record.user_metadata.creation_timestamp if hasattr(user_record, 'user_metadata') else None,
                'last_signin_time': user_record.user_metadata.last_sign_in_timestamp if hasattr(user_record, 'user_metadata') else None,
            },
            'polls': [
                {
                    'id': poll.id,
                    'question': poll.question,
                    'token': poll.token,
                    'stats_token': poll.stats_token,
                    'expires_at': poll.expires_at.isoformat() if poll.expires_at else None,
                    'paused': poll.paused,
                    'locked': poll.locked,
                    'options': [
                        {
                            'text': option.text,
                            'votes': option.votes
                        } for option in poll.options
                    ]
                } for poll in polls
            ],
            'privacy_preferences': {
                'functional_cookies': preferences.functional_cookies if preferences else True,
                'analytics_cookies': preferences.analytics_cookies if preferences else False,
                'auto_delete_polls': preferences.auto_delete_polls if preferences else False,
                'email_notifications': preferences.email_notifications if preferences else True,
                'data_retention_days': preferences.data_retention_days if preferences else 365,
                'consent_given_at': preferences.consent_given_at.isoformat() if preferences and preferences.consent_given_at else None,
                'consent_updated_at': preferences.consent_updated_at.isoformat() if preferences and preferences.consent_updated_at else None,
            },
            'data_processing_logs': [
                {
                    'action': log.action,
                    'legal_basis': log.legal_basis,
                    'data_categories': json.loads(log.data_categories) if log.data_categories else [],
                    'purpose': log.purpose,
                    'timestamp': log.timestamp.isoformat(),
                    'ip_address': log.ip_address
                } for log in logs
            ],
            'export_info': {
                'generated_at': datetime.utcnow().isoformat(),
                'format_version': '1.0'
            }
        }
        
        return export_data
    except Exception as e:
        print(f"Error exporting user data: {e}")
        return None

def delete_user_data(firebase_uid):
    """Delete all user data for GDPR right to erasure"""
    try:
        # Delete polls created by user
        polls = Poll.query.filter_by(firebase_uid=firebase_uid).all()
        for poll in polls:
            # Delete options first (foreign key constraint)
            for option in poll.options:
                db.session.delete(option)
            db.session.delete(poll)
        
        # Delete privacy preferences
        prefs = UserPrivacyPreferences.query.filter_by(firebase_uid=firebase_uid).first()
        if prefs:
            db.session.delete(prefs)
        
        # Delete data processing logs (keep anonymized for compliance)
        logs = DataProcessingLog.query.filter_by(firebase_uid=firebase_uid).all()
        for log in logs:
            log.firebase_uid = None  # Anonymize instead of delete
        
        # Delete data export requests
        requests = DataExportRequest.query.filter_by(firebase_uid=firebase_uid).all()
        for req in requests:
            db.session.delete(req)
        
        db.session.commit()
        
        # Also delete from Firebase (optional - user can do this themselves)
        # firebase_auth.delete_user(firebase_uid)
        
        return True
    except Exception as e:
        print(f"Error deleting user data: {e}")
        db.session.rollback()
        return False

# GDPR Routes
@app.route('/privacy-policy')
def privacy_policy():
    """Privacy policy page"""
    return render_template('privacy_policy.html', current_date=datetime.now())

@app.route('/privacy-settings', methods=['GET', 'POST'])
@require_email_verification
def privacy_settings():
    """Privacy settings and GDPR rights management"""
    firebase_uid = get_firebase_uid()
    if not firebase_uid:
        return redirect(url_for('login'))
    
    success = None
    error = None
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'update_cookies':
            prefs = get_user_privacy_preferences(firebase_uid)
            privacy_collection.update_one(
                {'firebase_uid': firebase_uid},
                {'$set': {
                    'functional_cookies': 'functional_cookies' in request.form,
                    'analytics_cookies': 'analytics_cookies' in request.form,
                    'consent_updated_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow(),
                }}
            )
            log_data_processing(
                firebase_uid, 
                'update_cookie_preferences', 
                'consent', 
                ['cookie_preferences'], 
                'User updated cookie consent preferences'
            )
            success = "Cookie preferences updated successfully"
        elif action == 'update_retention':
            prefs = get_user_privacy_preferences(firebase_uid)
            privacy_collection.update_one(
                {'firebase_uid': firebase_uid},
                {'$set': {
                    'auto_delete_polls': 'auto_delete_polls' in request.form,
                    'consent_updated_at': datetime.utcnow(),
                    'updated_at': datetime.utcnow(),
                }}
            )
            success = "Data retention settings updated successfully"
        elif action == 'download_data':
            # Create data export request
            export_request = DataExportRequest(
                firebase_uid=firebase_uid,
                request_type='export',
                status='processing'
            )
            db.session.add(export_request)
            db.session.commit()
            
            # Export data
            export_data = export_user_data(firebase_uid)
            if export_data:
                # Create temporary file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(export_data, f, indent=2, default=str)
                    temp_file = f.name
                
                export_request.status = 'completed'
                export_request.completed_at = datetime.utcnow()
                export_request.export_file_path = temp_file
                db.session.commit()
                
                log_data_processing(
                    firebase_uid, 
                    'data_export', 
                    'consent', 
                    ['all_user_data'], 
                    'User requested data export under GDPR Article 20'
                )
                
                return send_file(temp_file, as_attachment=True, download_name=f'tickvote_data_export_{firebase_uid[:8]}.json')
            else:
                export_request.status = 'failed'
                db.session.commit()
                error = "Failed to export data. Please try again."
                
        elif action == 'delete_account':
            if delete_user_data(firebase_uid):
                log_data_processing(
                    firebase_uid, 
                    'account_deletion', 
                    'consent', 
                    ['all_user_data'], 
                    'User requested account deletion under GDPR Article 17'
                )
                session.clear()
                return redirect(url_for('index'))
            else:
                error = "Failed to delete account. Please contact support."
                
        elif action == 'request_correction':
            # Create data correction request
            correction_request = DataExportRequest(
                firebase_uid=firebase_uid,
                request_type='correction',
                status='pending',
                notes='User requested data correction'
            )
            db.session.add(correction_request)
            db.session.commit()
            success = "Data correction request submitted. We will contact you within 30 days."
    
    # Get user info for display
    try:
        user_record = firebase_auth.get_user(firebase_uid)
        user_email = user_record.email if hasattr(user_record, 'email') else None
        user_name = get_user_display_name(firebase_uid)
        account_created = user_record.user_metadata.creation_timestamp if hasattr(user_record, 'user_metadata') else None
    except:
        user_email = None
        user_name = None
        account_created = None
    
    # Count polls for privacy settings using MongoDB
    polls_count = polls_collection.count_documents({'firebase_uid': firebase_uid})
    user_preferences = get_user_privacy_preferences(firebase_uid)
    
    return render_template('privacy_settings.html', 
                         firebase_uid=firebase_uid,
                         user_preferences=user_preferences,
                         user_email=user_email,
                         user_name=user_name,
                         account_created=account_created,
                         polls_count=polls_count,
                         success=success,
                         error=error)

@app.route('/api/cookie-consent', methods=['POST'])
def api_cookie_consent():
    """API endpoint to save cookie consent preferences"""
    try:
        data = request.get_json()
        firebase_uid = get_firebase_uid()
        
        if firebase_uid:
            prefs = get_user_privacy_preferences(firebase_uid)
            prefs.functional_cookies = data.get('functional', True)
            prefs.analytics_cookies = data.get('analytics', False)
            prefs.consent_updated_at = datetime.utcnow()
            db.session.commit()
            
            log_data_processing(
                firebase_uid, 
                'cookie_consent', 
                'consent', 
                ['cookie_preferences'], 
                'User provided cookie consent'
            )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error saving cookie consent: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/log-interaction', methods=['POST'])
def api_log_interaction():
    """API endpoint to log user interactions for analytics (GDPR compliant)"""
    try:
        data = request.get_json()
        firebase_uid = get_firebase_uid()
        
        # Only log if user has consented to analytics cookies
        if firebase_uid:
            prefs = get_user_privacy_preferences(firebase_uid)
            if prefs and prefs.analytics_cookies:
                log_data_processing(
                    firebase_uid,
                    f"analytics_{data.get('action', 'unknown')}",
                    'consent',
                    ['usage_data', 'technical_data'],
                    'Analytics and service improvement'
                )
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error logging interaction: {e}")
        return jsonify({'success': False}), 500

@app.context_processor
def inject_gdpr_context():
    """Inject GDPR-related context into all templates"""
    firebase_uid = get_firebase_uid()
    user_preferences = get_user_privacy_preferences(firebase_uid) if firebase_uid else None
    
    return {
        'user_preferences': user_preferences,
        'show_cookie_consent': not request.cookies.get('cookieConsent'),
        'privacy_policy_url': url_for('privacy_policy'),
        'privacy_settings_url': url_for('privacy_settings')
    }

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=Config.PORT, debug=Config.DEBUG)