import os
from dotenv import load_dotenv

# Load variables from .env file
load_dotenv()

# Get the base directory of the project
basedir = os.path.abspath(os.path.dirname(__file__))

class Config:
    # Load from environment or use a fallback (not recommended for secret keys in prod)
    SECRET_KEY = os.environ.get("SECRET_KEY") or "this-is-a-very-secret-key-change-me"

    # Database configuration
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or \
                              f"sqlite:///{os.path.join(basedir, 'app.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Flask-Mail configuration
    MAIL_SERVER = os.environ.get("MAIL_SERVER", "smtp.gmail.com")
    MAIL_PORT = int(os.environ.get("MAIL_PORT", 587))
    MAIL_USE_TLS = os.environ.get("MAIL_USE_TLS", "True").lower() in ["true", "1"]
    MAIL_USERNAME = os.environ.get("MAIL_USERNAME")
    MAIL_PASSWORD = os.environ.get("MAIL_PASSWORD")
    MAIL_DEFAULT_SENDER = os.environ.get("MAIL_DEFAULT_SENDER") or "noreply@example.com"

    # Other settings
    DEBUG = os.environ.get("DEBUG", "False").lower() in ["true", "1"]
