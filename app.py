import os
from flask import Flask, render_template, redirect, url_for, flash, request, send_file
from config import Config
from models import db, User
from forms import RegistrationForm, LoginForm, UploadForm, DecryptForm, ShareForm
from flask_migrate import Migrate
from flask_login import LoginManager, login_user, logout_user, current_user, login_required
from encryption import encrypt_file, decrypt_file, generate_rsa_keys, serialize_public_key, serialize_private_key
from flask_mail import Mail, Message
import io

app = Flask(__name__)
app.config.from_object(Config)

# Initialize extensions
db.init_app(app)
migrate = Migrate(app, db)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

mail = Mail(app)

# Create a folder for uploaded files
UPLOAD_FOLDER = os.path.join(os.getcwd(), "uploads")
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- Flask-Login Loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Routes ---

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/register', methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if user exists
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists.")
            return redirect(url_for("register"))

        # Generate RSA keys for the user for file encryption.
        private_key_obj, public_key_obj = generate_rsa_keys()
        public_key_pem = serialize_public_key(public_key_obj).decode("utf-8")
        private_key_pem = serialize_private_key(private_key_obj).decode("utf-8")

        user = User(
            username=form.username.data,
            email=form.email.data,
            public_key=public_key_pem,
            private_key=private_key_pem,
        )
        user.set_password(form.password.data)
        db.session.add(user)
        db.session.commit()
        flash("Registration successful. Please log in.")
        return redirect(url_for("login"))
    return render_template("register.html", form=form)

@app.route('/login', methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash("Invalid username or password.")
            return redirect(url_for("login"))
        login_user(user, remember=form.remember_me.data)
        flash("You have logged in successfully.")
        return redirect(url_for("index"))
    return render_template("login.html", form=form)

@app.route('/logout')
def logout():
    logout_user()
    flash("You have been logged out.")
    return redirect(url_for("index"))
from flask import send_file  # already imported in your file

@app.route('/upload', methods=["GET", "POST"])
@login_required
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        uploaded_file = request.files.get('file')
        if not uploaded_file:
            flash("No file uploaded.")
            return redirect(url_for("upload"))

        file_bytes = uploaded_file.read()

        # Use current user's public key for encryption.
        public_key_pem = current_user.public_key.encode("utf-8")

        # Use password encryption option if enabled.
        use_password = form.use_password.data
        password = form.password.data if use_password else None

        # Encrypt the file data
        result = encrypt_file(file_bytes, public_key_pem, use_password=use_password, password=password)

        # Save the encrypted data to a temporary in-memory buffer
        encrypted_buffer = io.BytesIO()
        encrypted_buffer.write(result["encrypted_data"])
        encrypted_buffer.write(b"\n===KEY===\n")
        encrypted_buffer.write(result["encrypted_sym_key"])
        if result["salt"]:
            encrypted_buffer.write(b"\n===SALT===\n")
            encrypted_buffer.write(result["salt"])
        encrypted_buffer.seek(0)

        # Send the file directly for download
        return send_file(
            encrypted_buffer,
            as_attachment=True,
            download_name=f"encrypted_{uploaded_file.filename}",
            mimetype="application/octet-stream"
        )

    return render_template("upload.html", form=form)

# @app.route('/upload', methods=["GET", "POST"])
# @login_required
# def upload():
#     form = UploadForm()
#     if form.validate_on_submit():
#         uploaded_file = request.files.get('file')
#         if not uploaded_file:
#             flash("No file uploaded.")
#             return redirect(url_for("upload"))
#         file_bytes = uploaded_file.read()

#         # Use current user's public key for encryption.
#         public_key_pem = current_user.public_key.encode("utf-8")

#         # Use password encryption option if enabled.
#         use_password = form.use_password.data
#         password = form.password.data if use_password else None

#         # Encrypt the file data
#         result = encrypt_file(file_bytes, public_key_pem, use_password=use_password, password=password)

#         # Save the encrypted data to a file
#         encrypted_filename = os.path.join(UPLOAD_FOLDER, f"encrypted_{uploaded_file.filename}")
#         with open(encrypted_filename, "wb") as f:
#             # For simplicity we write the encrypted file data, followed by a separator and then the encrypted symmetric key and salt (if any)
#             f.write(result["encrypted_data"] + b"\n===KEY===\n" + result["encrypted_sym_key"])
#             if result["salt"]:
#                 f.write(b"\n===SALT===\n" + result["salt"])
#         flash("File encrypted and uploaded successfully!")
#         return redirect(url_for("index"))
#     return render_template("upload.html", form=form)

@app.route('/decrypt', methods=["GET", "POST"])
@login_required
def decrypt():
    form = DecryptForm()
    if form.validate_on_submit():
        uploaded_file = request.files.get("file")
        if not uploaded_file:
            flash("No file uploaded for decryption.")
            return redirect(url_for("decrypt"))

        # Read and parse encrypted file
        content = uploaded_file.read().split(b"\n===KEY===\n")
        if len(content) < 2:
            flash("Invalid encrypted file format.")
            return redirect(url_for("decrypt"))

        encrypted_data = content[0]
        key_parts = content[1].split(b"\n===SALT===\n")
        encrypted_sym_key = key_parts[0]
        salt = key_parts[1] if len(key_parts) > 1 else None

        # Check if password was used
        use_password = True if form.password.data else False
        password = form.password.data if use_password else None

        private_key_pem = current_user.private_key.encode("utf-8")

        try:
            decrypted_data = decrypt_file(
                encrypted_data,
                encrypted_sym_key,
                private_key_pem,
                use_password=use_password,
                password=password,
                salt=salt
            )
        except Exception as e:
            flash("Decryption failed. Check your key or password.")
            return redirect(url_for("decrypt"))

        # Prepare decrypted data for download
        decrypted_buffer = io.BytesIO(decrypted_data)
        decrypted_buffer.seek(0)

        # Guess original name (optional improvement: store this in metadata)
        original_name = uploaded_file.filename.replace("encrypted_", "").replace(".enc", "")

        return send_file(
            decrypted_buffer,
            as_attachment=True,
            download_name=f"decrypted_{original_name}",
            mimetype="application/octet-stream"
        )

    return render_template("decrypt.html", form=form)

@app.route('/share', methods=["GET", "POST"])
@login_required
def share():
    form = ShareForm()
    if form.validate_on_submit():
        recipient = form.recipient_email.data
        message_body = form.message.data
        file = request.files.get("file")

        if not file:
            flash("Please select a file to share.")
            return redirect(url_for("share"))

        # Prepare and send the email
        try:
            msg = Message(
                subject="Encrypted File from " + current_user.username,
                recipients=[recipient],
                body=message_body or "Encrypted file attached."
            )
            msg.attach(
                filename=file.filename,
                content_type="application/octet-stream",
                data=file.read()
            )
            mail.send(msg)
            flash("Encrypted file shared successfully via email!")
        except Exception as e:
            flash("Email sending failed: " + str(e))
        return redirect(url_for("index"))

    return render_template("share.html", form=form)

if __name__ == '__main__':
    app.run()
