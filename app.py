from flask import Flask, render_template, redirect, url_for, request, flash, make_response, jsonify
from models import db, Poll, Option
from datetime import datetime, timedelta
import secrets
import requests
from flask import abort
from dotenv import load_dotenv
from flask_migrate import Migrate
import os

load_dotenv()  # load env

app = Flask(__name__)

migrate = Migrate(app, db)
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'sqlite:///../instance/tickvote.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'changeme')
db.init_app(app)

RECAPTCHA_SECRET_KEY = os.getenv('RECAPTCHA_SECRET_KEY')  # Set this in the .env file - look in readme

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

@app.route('/create', methods=['GET', 'POST'])
def create_poll():
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
            return add_owner_token_cookie(resp, owner_token)
        return render_template('create_poll.html', error="Please provide a question and at least one option.")
    return render_template('create_poll.html')

@app.route('/dashboard')
def dashboard():
    tokens = get_owner_tokens()
    if tokens:
        polls = Poll.query.filter(Poll.owner_token.in_(tokens)).all()
    else:
        polls = []
    return render_template('dashboard.html', polls=polls)

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
    can_vote = not (expired or paused or locked or already_voted)
    if request.method == 'POST' and can_vote:
        option_id = request.form.get('option')
        option = Option.query.filter_by(id=option_id, poll_id=poll.id).first()
        if option:
            option.votes += 1
            db.session.commit()
        resp = make_response(redirect(url_for('view_poll_token', token=token)))
        return add_voted_token_cookie(resp, poll.token)
    return render_template('poll.html', poll=poll, expired=expired, paused=paused, locked=locked, already_voted=already_voted)

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

@app.route('/admin')
def admin_dashboard():
    polls = Poll.query.all()
    return render_template('admin_dashboard.html', polls=polls)

@app.route('/admin/poll/<int:poll_id>/edit', methods=['GET', 'POST'])
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
def admin_delete_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    Option.query.filter_by(poll_id=poll.id).delete()
    db.session.delete(poll)
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/poll/<int:poll_id>/lock', methods=['POST'])
def admin_lock_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    poll.locked = True
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/poll/<int:poll_id>/unlock', methods=['POST'])
def admin_unlock_poll(poll_id):
    poll = Poll.query.get_or_404(poll_id)
    poll.locked = False
    db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/option/<int:option_id>/add_vote', methods=['POST'])
def admin_add_vote(option_id):
    option = Option.query.get_or_404(option_id)
    option.votes += 1
    db.session.commit()
    return redirect(request.referrer or url_for('admin_dashboard'))

@app.route('/admin/option/<int:option_id>/remove_vote', methods=['POST'])
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run()