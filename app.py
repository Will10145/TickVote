from flask import Flask, render_template, redirect, url_for, request, flash, make_response, jsonify, session
from models import db, Poll, Option, User
from datetime import datetime, timedelta
import secrets
import requests
from flask import abort
from dotenv import load_dotenv
from flask_migrate import Migrate
import smtplib, ssl
import os
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

load_dotenv()  # load env

app = Flask(__name__)

migrate = Migrate(app, db)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///../instance/tickvote.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'changeme')
db.init_app(app)

RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')  # Set this in the .env file - look in readme
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'changeme')

FIREBASE_CRED_PATH = os.getenv('FIREBASE_CRED_PATH', 'firebase_service_account.json')
if os.path.exists(FIREBASE_CRED_PATH):
    if not firebase_admin._apps:
        cred = credentials.Certificate(FIREBASE_CRED_PATH)
        firebase_admin.initialize_app(cred)
else:
    # Try to find the .json file with a double extension (common mistake)
    alt_path = FIREBASE_CRED_PATH + '.json'
    if os.path.exists(alt_path):
        if not firebase_admin._apps:
            cred = credentials.Certificate(alt_path)
            firebase_admin.initialize_app(cred)
    else:
        print(f"Warning: Firebase service account file '{FIREBASE_CRED_PATH}' not found. Firebase features will be disabled.")

def send_email(to_email, subject, body):
    """
    Send an email using SMTP settings from environment variables.
    Uses STARTTLS if SMTP_USE_TLS is set to 1 (default).
    """
    smtp_server = os.getenv('SMTP_SERVER')
    smtp_port = int(os.getenv('SMTP_PORT', 587))
    smtp_user = os.getenv('SMTP_USER')
    smtp_password = os.getenv('SMTP_PASSWORD')
    from_email = os.getenv('FROM_EMAIL', smtp_user)
    use_tls = os.getenv('SMTP_USE_TLS', '1') == '1'

    if not all([smtp_server, smtp_port, smtp_user, smtp_password, to_email]):
        raise RuntimeError("Missing SMTP configuration or recipient email.")

    message = f"From: {from_email}\r\nTo: {to_email}\r\nSubject: {subject}\r\n\r\n{body}"

    context = ssl.create_default_context()
    with smtplib.SMTP(smtp_server, smtp_port) as server:
        if use_tls:
            server.starttls(context=context)
        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, to_email, message)

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
    payload = {
        'secret': RECAPTCHA_SECRET_KEY,
        'response': response_token
    }
    r = requests.post('https://www.google.com/recaptcha/api/siteverify', data=payload)
    result = r.json()
    return result.get('success', False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login/firebase', methods=['POST'])
def firebase_login():
    id_token = request.json.get('idToken')
    try:
        decoded_token = firebase_auth.verify_id_token(id_token)
        session['firebase_uid'] = decoded_token['uid']
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 401

@app.route('/logout/firebase')
def firebase_logout():
    session.pop('firebase_uid', None)
    return redirect(url_for('index'))

def get_firebase_uid():
    return session.get('firebase_uid')

@app.route('/create', methods=['GET', 'POST'])
def create_poll():
    firebase_uid = get_firebase_uid()
    if request.method == 'POST':
        # Verify reCAPTCHA
        recaptcha_response = request.form.get('g-recaptcha-response')
        if not recaptcha_response or not verify_recaptcha(recaptcha_response):
            return render_template('create_poll.html', error="reCAPTCHA verification failed. Please try again.")
        question = request.form.get('question')
        options = request.form.getlist('options')
        expiry_hours = request.form.get('expiry')
        try:
            expiry_hours = int(expiry_hours)
            if expiry_hours < 1 or expiry_hours > 168:
                raise ValueError()
        except Exception:
            return render_template('create_poll.html', error="Expiry must be between 1 and 168 hours.")
        if question and options and any(opt.strip() for opt in options):
            poll_token = generate_token()
            stats_token = generate_token()
            owner_token = generate_token()
            expiry_time = datetime.utcnow() + timedelta(hours=expiry_hours)
            poll = Poll(
                question=question,
                token=poll_token,
                stats_token=stats_token,
                owner_token=owner_token,
                expires_at=expiry_time
            )
            if firebase_uid:
                poll.firebase_uid = firebase_uid
            db.session.add(poll)
            db.session.flush()
            for opt_text in options:
                if opt_text.strip():
                    option = Option(poll_id=poll.id, text=opt_text.strip())
                    db.session.add(option)
            db.session.commit()
            poll_url = url_for('view_poll_token', token=poll_token, _external=True)
            stats_url = url_for('poll_stats', stats_token=stats_token, _external=True)
            resp = make_response(render_template('poll_created.html', poll_url=poll_url, stats_url=stats_url, expiry=expiry_time))
            if not firebase_uid:
                return add_owner_token_cookie(resp, owner_token)
            return resp
        return render_template('create_poll.html', error="Please provide a question and at least one option.")
    return render_template('create_poll.html')

@app.route('/dashboard')
def dashboard():
    try:
        firebase_uid = get_firebase_uid()
        user_id = get_user_id()
        tokens = get_owner_tokens()
        if not firebase_uid and not user_id and not tokens:
            return redirect(url_for('login'))
        if firebase_uid:
            polls = Poll.query.filter_by(firebase_uid=firebase_uid).all()
        elif user_id:
            polls = Poll.query.filter_by(owner_token=str(user_id)).all()
        else:
            if tokens:
                polls = Poll.query.filter(Poll.owner_token.in_(tokens)).all()
            else:
                polls = []
        return render_template('dashboard.html', polls=polls)
    except Exception as e:
        print("Error in /dashboard:", e)
        return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Username/password login
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if username and password:
            user = User.query.filter_by(username=username).first()
            if user and check_password_hash(user.password_hash, password):
                session['user_id'] = user.id
                return redirect(url_for('dashboard'))
            else:
                return render_template('login.html', error="Invalid username or password.")
        # ...Firebase login handled by JS...
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        if not username or not password:
            return render_template('signup.html', error="Username and password required.")
        if len(username) < 3 or len(password) < 4:
            return render_template('signup.html', error="Username or password too short.")
        user = User(username=username, password_hash=generate_password_hash(password))
        db.session.add(user)
        try:
            db.session.commit()
        except IntegrityError:
            db.session.rollback()
            return render_template('signup.html', error="Username already exists.")
        session['user_id'] = user.id
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

def get_user_id():
    return session.get('user_id')

@app.route('/poll/<int:poll_id>', methods=['GET', 'POST'])
def view_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    expired = poll.expires_at and poll.expires_at < datetime.utcnow()
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
    expired = poll.expires_at and poll.expires_at < datetime.utcnow()
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
    if request.method == 'POST':
        password = request.form.get('password')
        if password == ADMIN_PASSWORD:
            session['admin_logged_in'] = True
            return redirect(url_for('admin_dashboard'))
        else:
            error = "Incorrect password."
    return render_template('admin_login.html', error=error)

@app.route('/admin/logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    return redirect(url_for('admin_login'))

def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin_logged_in'):
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
    return dict(RECAPTCHA_SITE_KEY=os.getenv('RECAPTCHA_SITE_KEY', ''))

@app.route('/about')
def about():
    return render_template('about.html')

@app.errorhandler(404)
def error_four_oh_four(s):
    return render_template('404.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()