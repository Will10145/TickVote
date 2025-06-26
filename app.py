from flask import Flask, render_template, redirect, url_for, request, make_response, jsonify, session
from models import db, Poll, Option
from datetime import datetime, timezone, timedelta
import secrets
import requests
import os
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from dotenv import load_dotenv
from flask_migrate import Migrate
from functools import wraps

# Load environment variables
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
migrate = Migrate(app, db)

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
        decoded_token = firebase_auth.verify_id_token(id_token)
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
        # Skip reCAPTCHA verification for now to make it easier to test
        # recaptcha_response = request.form.get('g-recaptcha-response')
        # if not recaptcha_response or not verify_recaptcha(recaptcha_response):
        #     return render_template('create_poll.html', error="reCAPTCHA verification failed. Please try again.")
        
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
            # Create poll
            poll_token = generate_token()
            stats_token = generate_token()
            owner_token = generate_token()
            expiry_time = datetime.now(timezone.utc) + timedelta(hours=expiry_hours)
            
            poll = Poll(
                question=question,
                token=poll_token,
                stats_token=stats_token,
                owner_token=owner_token,
                expires_at=expiry_time,
                firebase_uid=firebase_uid  # Will be None if not authenticated
            )
            
            db.session.add(poll)
            db.session.flush()
            
            # Add options
            for opt_text in options:
                option = Option(poll_id=poll.id, text=opt_text)
                db.session.add(option)
            
            db.session.commit()
            
            # Generate URLs and response
            poll_url = url_for('view_poll_token', token=poll_token, _external=True)
            stats_url = url_for('poll_stats', stats_token=stats_token, _external=True)
            resp = make_response(render_template('poll_created.html', 
                                               poll_url=poll_url, 
                                               stats_url=stats_url, 
                                               expiry=expiry_time))
            
            # Always set the owner token cookie, regardless of authentication status
            resp = add_owner_token_cookie(resp, owner_token)
            return resp
            
        except Exception as e:
            db.session.rollback()
            print(f"Error creating poll: {e}")
            return render_template('create_poll.html', error="An error occurred while creating the poll. Please try again.")
    
    return render_template('create_poll.html')

@app.route('/dashboard')
@require_email_verification
def dashboard():
    try:
        firebase_uid = get_firebase_uid()
        tokens = get_owner_tokens()
        
        # Collect polls from all sources
        polls = []
        
        # Get Firebase user polls
        if firebase_uid:
            firebase_polls = Poll.query.filter_by(firebase_uid=firebase_uid).all()
            polls.extend(firebase_polls)
        
        # Get anonymous user polls via cookies
        if tokens:
            token_polls = Poll.query.filter(Poll.owner_token.in_(tokens)).all()
            polls.extend(token_polls)
        
        # Remove duplicates while preserving order
        seen_ids = set()
        unique_polls = []
        for poll in polls:
            if poll.id not in seen_ids:
                unique_polls.append(poll)
                seen_ids.add(poll.id)
        
        # Show login prompt if user has no polls and is not authenticated
        show_login_prompt = not unique_polls and not firebase_uid and not tokens
        
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
    poll = Poll.query.get_or_404(poll_id)
    # Handle both timezone-aware and naive datetimes
    if poll.expires_at:
        if poll.expires_at.tzinfo is None:
            # Database datetime is naive, assume it's UTC
            poll_expires_utc = poll.expires_at.replace(tzinfo=timezone.utc)
        else:
            poll_expires_utc = poll.expires_at
        expired = poll_expires_utc < datetime.now(timezone.utc)
    else:
        expired = False
    paused = poll.paused
    locked = poll.locked
    voted_tokens = get_voted_tokens()
    already_voted = poll.token in voted_tokens
    can_vote = not (expired or paused or locked or already_voted)
    if request.method == 'POST' and can_vote:
        option_id = request.form.get('option')
        option = Option.query.filter_by(id=option_id, poll_id=poll_id).first()
        if option:
            option.votes += 1
            db.session.commit()
        resp = make_response(redirect(url_for('view_poll', poll_id=poll_id)))
        return add_voted_token_cookie(resp, poll.token)
    return render_template('poll.html', poll=poll, expired=expired, paused=paused, locked=locked, already_voted=already_voted)

@app.route('/poll/token/<token>', methods=['GET', 'POST'])
def view_poll_token(token):
    poll = Poll.query.filter_by(token=token).first_or_404()
    # Handle both timezone-aware and naive datetimes
    if poll.expires_at:
        if poll.expires_at.tzinfo is None:
            # Database datetime is naive, assume it's UTC
            poll_expires_utc = poll.expires_at.replace(tzinfo=timezone.utc)
        else:
            poll_expires_utc = poll.expires_at
        expired = poll_expires_utc < datetime.now(timezone.utc)
    else:
        expired = False
    paused = poll.paused
    locked = poll.locked
    voted_tokens = get_voted_tokens()
    already_voted = poll.token in voted_tokens
    just_voted = False
    can_vote = not (expired or paused or locked or already_voted)
    if request.method == 'POST':
        if can_vote:
            option_id = request.form.get('option')
            option = Option.query.filter_by(id=option_id, poll_id=poll.id).first()
            if option:
                option.votes += 1
                db.session.commit()
            resp = make_response(redirect(url_for('view_poll_token', token=token, voted='1')))
            return add_voted_token_cookie(resp, poll.token)
        else:
            # User tried to vote again
            return render_template('poll.html', poll=poll, expired=expired, paused=paused, locked=locked, already_voted=already_voted, tried_to_vote_again=True)
    # Check if redirected after voting
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
    polls = Poll.query.all()
    return render_template('admin_dashboard.html', polls=polls)

@app.route('/admin/poll/<int:poll_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    if request.method == 'POST':
        question = request.form.get('question')
        if question:
            poll.question = question
        for option in poll.options:
            new_text = request.form.get(f'option_text_{option.id}')
            if new_text:
                option.text = new_text
        db.session.commit()
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_edit_poll.html', poll=poll)

@app.route('/admin/poll/<int:poll_id>/delete', methods=['POST'])
@admin_required
def admin_delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    Option.query.filter_by(poll_id=poll.id).delete()
    db.session.delete(poll)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/poll/<int:poll_id>/lock', methods=['POST'])
@admin_required
def admin_lock_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    poll.locked = True
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/poll/<int:poll_id>/unlock', methods=['POST'])
@admin_required
def admin_unlock_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    poll.locked = False
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/option/<int:option_id>/add_vote', methods=['POST'])
@admin_required
def admin_add_vote(option_id):
    option = Option.query.get_or_404(option_id)
    option.votes += 1
    db.session.commit()
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/option/<int:option_id>/remove_vote', methods=['POST'])
@admin_required
def admin_remove_vote(option_id):
    option = Option.query.get_or_404(option_id)
    if option.votes > 0:
        option.votes -= 1
        db.session.commit()
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/stats/<stats_token>', methods=['GET', 'POST'])
def poll_stats(stats_token):
    poll = Poll.query.filter_by(stats_token=stats_token).first_or_404()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'delete':
            Option.query.filter_by(poll_id=poll.id).delete()
            db.session.delete(poll)
            db.session.commit()
            return render_template('poll_deleted.html')
        elif action == 'pause':
            poll.paused = True
            db.session.commit()
        elif action == 'unpause':
            poll.paused = False
            db.session.commit()
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(port=Config.PORT, debug=Config.DEBUG)