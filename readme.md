# TickVote: A Simple Poll App ✅

## Installation

Edit the .env file as accordingly:
```
FLASK_SECRET_KEY=[SET THIS TO ANYTHING!]
RECAPTCHA_SITE_KEY=
RECAPTCHA_SECRET_KEY=
DATABASE_URL=sqlite:///../instance/tickvote.db
```
Get your recaptcha key from [here](https://www.google.com/recaptcha/admin/create) <br>
Once you have editited the .env file, run this command in your terminal to set up your enviroment
```bash
git clone https://github.com/Will10145/TickVote.git
cd TickVote
bash setup.sh
```
To start the flask server run
```bash
gunicorn -b ":${PORT:-5000}" app:app
```
