python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
export FLASK_APP=app.py
export FLASK_ENV=development
flask db upgrade || true
gunicorn -b ":${PORT:-5000}" app:app