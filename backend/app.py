from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from functools import wraps
from sqlalchemy import select, and_, delete
from models import User, Password, MFATOTP
from database import get_session
import security
from email_service import email_service
from datetime import datetime, timedelta, timezone
import os
import logging
from logging.handlers import RotatingFileHandler
from dotenv import load_dotenv
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import validators

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Load from environment

if not app.secret_key:
    raise ValueError("FLASK_SECRET_KEY must be set in environment variables")

# Configure CSRF Protection
csrf = CSRFProtect(app)

# Configure Rate Limiting
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Configure Security Headers
# Reads from environment variables for production deployment
Talisman(app, 
    force_https=os.getenv('FORCE_HTTPS', 'False').lower() == 'true',
    strict_transport_security=os.getenv('STRICT_TRANSPORT_SECURITY', 'False').lower() == 'true',
    content_security_policy={
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'", "cdnjs.cloudflare.com", "code.jquery.com", "cdn.jsdelivr.net"],
        'style-src': ["'self'", "'unsafe-inline'", "fonts.googleapis.com", "cdnjs.cloudflare.com", "cdn.jsdelivr.net"],
        'font-src': ["'self'", "fonts.gstatic.com", "cdnjs.cloudflare.com"],
        'img-src': ["'self'", "data:"],
    }
)

# Configure Session Security
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Configure secure logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/securevault.log', maxBytes=10240000, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('SecureVault Pro startup')

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Email verification required decorator
def email_verification_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        
        with get_session() as db:
            result = db.execute(select(User).where(User.id == session['user_id']))
            user = result.scalar_one_or_none()
            
            if not user or not user.is_email_verified:
                flash('Please verify your email address to access this feature.', 'warning')
                return redirect(url_for('dashboard'))
        
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        with get_session() as db:
            result = db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()

            if user and security.verify_password(password, user.password_hash):
                # Check if email is verified
                if not user.is_email_verified:
                    flash('Please verify your email address before logging in. Check your inbox for the verification link.', 'warning')
                    return render_template('login.html')
                
                # Check if user has 2FA enabled
                result = db.execute(select(MFATOTP).where(MFATOTP.user_id == user.id))
                mfa = result.scalar_one_or_none()
                
                if mfa and mfa.is_enabled:
                    # Store user info temporarily and redirect to 2FA verification
                    session['temp_user_id'] = user.id
                    session['temp_user_email'] = user.email
                    return redirect(url_for('verify_2fa'))
                else:
                    # Normal login - set session and redirect
                    session['user_id'] = user.id
                    session['user_email'] = user.email
                    return redirect(url_for('dashboard'))

        flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        # Validate email format
        is_valid_email, email_error = validators.validate_email_format(email)
        if not is_valid_email:
            flash(f'Invalid email: {email_error}', 'error')
            return render_template('signup.html')
        
        # Validate password strength
        is_valid_password, password_error = validators.validate_password_strength(password)
        if not is_valid_password:
            flash(f'Invalid password: {password_error}', 'error')
            return render_template('signup.html')
        
        # Sanitize email
        email = validators.sanitize_string(email, 255)

        with get_session() as db:
            result = db.execute(select(User).where(User.email == email))
            existing_user = result.scalar_one_or_none()

            if existing_user:
                flash('Email already exists', 'error')
                return render_template('signup.html')

            # Create new user with email verification
            hashed_password = security.get_password_hash(password)
            verification_token = security.generate_verification_token()
            verification_expires = datetime.now(timezone.utc) + timedelta(hours=24)
            
            new_user = User(
                email=email, 
                password_hash=hashed_password,
                email_verification_token=verification_token,
                email_verification_expires=verification_expires
            )
            db.add(new_user)
            db.commit()
            db.refresh(new_user)

            # Send verification email
            try:
                app.logger.info(f'Attempting to send verification email to user')
                email_sent = email_service.send_verification_email(email, verification_token)
                if email_sent:
                    app.logger.info('Verification email sent successfully')
                    flash('Account created successfully! Please check your email to verify your account.', 'success')
                else:
                    app.logger.warning('Failed to send verification email')
                    # TEMPORARY: Auto-verify in development mode when email fails
                    if os.getenv('FLASK_DEBUG', 'False').lower() == 'true':
                        new_user.is_verified = True
                        db.commit()
                        app.logger.info('⚠️ DEV MODE: Auto-verified user due to email failure')
                        flash('Account created successfully! (Email verification bypassed in dev mode)', 'success')
                    else:
                        flash('Account created but verification email failed to send. Please try resending the verification email from the login page.', 'warning')
            except Exception as e:
                app.logger.error(f'Email sending error: {str(e)}')
                # TEMPORARY: Auto-verify in development mode when email fails
                if os.getenv('FLASK_DEBUG', 'False').lower() == 'true':
                    new_user.is_verified = True
                    db.commit()
                    app.logger.info('⚠️ DEV MODE: Auto-verified user due to email failure')
                    flash('Account created successfully! (Email verification bypassed in dev mode)', 'success')
                else:
                    flash('Account created but verification email failed. Please try resending the verification email from the login page.', 'warning')

            return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# API Routes for Password CRUD
@app.route('/api/passwords', methods=['GET'])
@csrf.exempt
@login_required
def get_passwords():
    with get_session() as db:
        result = db.execute(select(Password).where(Password.user_id == session['user_id']))
        passwords = result.scalars().all()

    password_list = [
        {
            'id': pwd.id,
            'website_name': pwd.website_name,
            'username': pwd.username,
            'password': security.decrypt_password(pwd.encrypted_password)
        }
        for pwd in passwords
    ]

    return jsonify(password_list)

@app.route('/api/passwords', methods=['POST'])
@csrf.exempt
@login_required
def create_password():
    data = request.get_json()
    
    # Validate website name
    is_valid_website, website_error = validators.validate_website_name(data.get('website_name', ''))
    if not is_valid_website:
        return jsonify({'error': website_error}), 400
    
    # Validate username
    is_valid_username, username_error = validators.validate_username_field(data.get('username', ''))
    if not is_valid_username:
        return jsonify({'error': username_error}), 400
    
    # Validate password
    if not data.get('password') or not data.get('password').strip():
        return jsonify({'error': 'Password is required'}), 400
    
    if len(data.get('password', '')) < 4:
        return jsonify({'error': 'Password must be at least 4 characters long'}), 400
    
    # Sanitize inputs
    website_name = validators.sanitize_string(data['website_name'], 255)
    username = validators.sanitize_string(data['username'], 255)
    
    with get_session() as db:
        encrypted_pwd = security.encrypt_password(data['password'])
        new_password = Password(
            user_id=session['user_id'],
            website_name=website_name,
            username=username,
            encrypted_password=encrypted_pwd
        )
        db.add(new_password)
        db.commit()
        db.refresh(new_password)

    return jsonify({'id': new_password.id, 'message': 'Password created successfully'})

@app.route('/api/passwords/<int:password_id>', methods=['PUT'])
@csrf.exempt
@login_required
def update_password(password_id):
    data = request.get_json()
    
    # Validate required fields
    if not data.get('website_name') or not data.get('website_name').strip():
        return jsonify({'error': 'Website name is required'}), 400
    
    if not data.get('username') or not data.get('username').strip():
        return jsonify({'error': 'Username is required'}), 400
    
    if not data.get('password') or not data.get('password').strip():
        return jsonify({'error': 'Password is required'}), 400
    
    if len(data.get('password', '')) < 4:
        return jsonify({'error': 'Password must be at least 4 characters long'}), 400
    
    with get_session() as db:
        result = db.execute(
            select(Password).where(
                Password.id == password_id,
                Password.user_id == session['user_id']
            )
        )
        password = result.scalar_one_or_none()

        if not password:
            return jsonify({'error': 'Password not found'}), 404

        password.website_name = data['website_name'].strip()
        password.username = data['username'].strip()
        password.encrypted_password = security.encrypt_password(data['password'])
        db.commit()

    return jsonify({'message': 'Password updated successfully'})

@app.route('/api/passwords/<int:password_id>', methods=['DELETE'])
@csrf.exempt
@login_required
def delete_password(password_id):
    with get_session() as db:
        result = db.execute(
            select(Password).where(
                Password.id == password_id,
                Password.user_id == session['user_id']
            )
        )
        password = result.scalar_one_or_none()

        if not password:
            return jsonify({'error': 'Password not found'}), 404

        db.delete(password)
        db.commit()

    return jsonify({'message': 'Password deleted successfully'})

# Email verification route
@app.route('/verify-email/<token>')
def verify_email(token):
    with get_session() as db:
        result = db.execute(
            select(User).where(
                User.email_verification_token == token,
                User.email_verification_expires > datetime.now(timezone.utc)
            )
        )
        user = result.scalar_one_or_none()
        
        if user:
            user.is_email_verified = True
            user.email_verification_token = None
            user.email_verification_expires = None
            db.commit()
            flash('Email verified successfully! You can now login.', 'success')
        else:
            flash('Invalid or expired verification link.', 'error')
    
    return redirect(url_for('login'))

# Resend verification email
@app.route('/resend-verification', methods=['POST'])
@limiter.limit("3 per minute")
def resend_verification():
    app.logger.info('Resend verification route accessed')
    email = request.form.get('email')
    
    try:
        with get_session() as db:
            result = db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            
            if user and not user.is_email_verified:
                app.logger.info('Resending verification email to user')
                verification_token = security.generate_verification_token()
                verification_expires = datetime.now(timezone.utc) + timedelta(hours=24)
                
                user.email_verification_token = verification_token
                user.email_verification_expires = verification_expires
                db.commit()
                
                try:
                    email_sent = email_service.send_verification_email(email, verification_token)
                    if email_sent:
                        app.logger.info('Resend verification email sent successfully')
                        flash('Verification email sent successfully! Please check your inbox.', 'success')
                    else:
                        app.logger.warning('Failed to resend verification email')
                        # TEMPORARY: Auto-verify in development mode when email fails
                        if os.getenv('FLASK_DEBUG', 'False').lower() == 'true':
                            user.is_email_verified = True
                            user.email_verification_token = None
                            user.email_verification_expires = None
                            db.commit()
                            app.logger.info('⚠️ DEV MODE: Auto-verified user due to email failure')
                            flash('Account verified successfully! (Email verification bypassed in dev mode)', 'success')
                        else:
                            flash('Failed to send verification email. Please try again later.', 'error')
                except Exception as e:
                    app.logger.error(f'Email sending error in resend: {str(e)}')
                    # TEMPORARY: Auto-verify in development mode when email fails
                    if os.getenv('FLASK_DEBUG', 'False').lower() == 'true':
                        user.is_email_verified = True
                        user.email_verification_token = None
                        user.email_verification_expires = None
                        db.commit()
                        app.logger.info('⚠️ DEV MODE: Auto-verified user due to email failure')
                        flash('Account verified successfully! (Email verification bypassed in dev mode)', 'success')
                    else:
                        flash('Failed to send verification email. Please try again later.', 'error')
            elif user and user.is_email_verified:
                app.logger.info('User already verified')
                flash('Your email is already verified. You can log in.', 'info')
            else:
                app.logger.warning('Email not found in resend verification')
                flash('Email address not found. Please check and try again.', 'error')
                
    except Exception as e:
        app.logger.error(f'Database error in resend_verification: {str(e)}')
        flash('A database error occurred. Please try again.', 'error')
    
    return redirect(url_for('login'))

# Forgot password route
@app.route('/forgot-password', methods=['GET', 'POST'])
@limiter.limit("3 per minute")
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        
        with get_session() as db:
            result = db.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            
            if user:
                reset_token = security.generate_password_reset_token()
                reset_expires = datetime.now(timezone.utc) + timedelta(hours=1)
                
                user.password_reset_token = reset_token
                user.password_reset_expires = reset_expires
                db.commit()
                
                try:
                    email_sent = email_service.send_password_reset_email(email, reset_token)
                    if email_sent:
                        flash('Password reset link sent to your email!', 'success')
                    else:
                        flash('Failed to send reset email. Please try again.', 'error')
                except Exception as e:
                    app.logger.error(f'Failed to send password reset email: {str(e)}')
                    flash('Failed to send reset email. Please try again.', 'error')
            else:
                # Don't reveal if email exists or not
                flash('If an account with that email exists, a reset link has been sent.', 'info')
        
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

# Reset password route
@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    with get_session() as db:
        result = db.execute(
            select(User).where(
                User.password_reset_token == token,
                User.password_reset_expires > datetime.now(timezone.utc)
            )
        )
        user = result.scalar_one_or_none()
        
        if not user:
            flash('Invalid or expired reset link.', 'error')
            return redirect(url_for('login'))
        
        if request.method == 'POST':
            new_password = request.form.get('password')
            
            user.password_hash = security.get_password_hash(new_password)
            user.password_reset_token = None
            user.password_reset_expires = None
            db.commit()
            
            flash('Password reset successfully! Please login with your new password.', 'success')
            return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# Change password route (for logged in users)
@app.route('/change-password', methods=['POST'])
@login_required
def change_password():
    current_password = request.form.get('current_password')
    new_password = request.form.get('new_password')
    
    with get_session() as db:
        result = db.execute(select(User).where(User.id == session['user_id']))
        user = result.scalar_one_or_none()
        
        if user and security.verify_password(current_password, user.password_hash):
            user.password_hash = security.get_password_hash(new_password)
            db.commit()
            flash('Password changed successfully!', 'success')
        else:
            flash('Current password is incorrect.', 'error')
    
    return redirect(url_for('dashboard'))

# 2FA Setup routes
@app.route('/setup-2fa', methods=['GET', 'POST'])
@login_required
def setup_2fa():
    with get_session() as db:
        result = db.execute(select(User).where(User.id == session['user_id']))
        user = result.scalar_one_or_none()
        
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('dashboard'))
        
        # Check if 2FA already exists
        result = db.execute(select(MFATOTP).where(MFATOTP.user_id == user.id))
        mfa = result.scalar_one_or_none()
        
        if request.method == 'POST':
            if mfa and mfa.is_enabled:
                # Disable 2FA
                mfa.disable()
                db.commit()
                flash('Two-Factor Authentication disabled', 'success')
                return redirect(url_for('dashboard'))
            else:
                # Enable 2FA - verify token first
                token = request.form.get('token')
                if not mfa:
                    flash('Please scan QR code first', 'error')
                    return redirect(url_for('setup_2fa'))
                
                if mfa.verify_token(token):
                    mfa.enable()
                    db.commit()
                    flash('Two-Factor Authentication enabled!', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Invalid verification code', 'error')
                    return render_template('setup_2fa.html', mfa=mfa, user=user)
        
        # Create new 2FA setup if doesn't exist
        if not mfa:
            mfa = MFATOTP(user.id)
            db.add(mfa)
            db.commit()
            db.refresh(mfa)
        
        return render_template('setup_2fa.html', mfa=mfa, user=user)

@app.route('/verify-2fa', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify_2fa():
    # Check if user is in temporary 2FA verification state
    if 'temp_user_id' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        token = request.form.get('token')
        backup_code = request.form.get('backup_code')
        
        with get_session() as db:
            result = db.execute(select(MFATOTP).where(MFATOTP.user_id == session['temp_user_id']))
            mfa = result.scalar_one_or_none()
            
            if not mfa or not mfa.is_enabled:
                flash('2FA not properly configured', 'error')
                return redirect(url_for('login'))
            
            # Verify TOTP token
            if token and mfa.verify_token(token):
                mfa.record_usage()
                db.commit()
                session['user_id'] = session.pop('temp_user_id')
                session['user_email'] = session.pop('temp_user_email')
                flash('Login successful!', 'success')
                return redirect(url_for('dashboard'))
            
            # Verify backup code
            elif backup_code and mfa.verify_backup_code(backup_code):
                mfa.record_usage()
                db.commit()
                session['user_id'] = session.pop('temp_user_id')
                session['user_email'] = session.pop('temp_user_email')
                flash('Login successful with backup code!', 'warning')
                return redirect(url_for('dashboard'))
            
            else:
                flash('Invalid verification code or backup code', 'error')
    
    return render_template('verify_2fa.html')

@app.route('/terms')
def terms():
    return render_template('terms.html')

@app.route('/privacy')
def privacy():
    return render_template('privacy.html')

@app.route('/api/2fa-status')
@csrf.exempt
@login_required
def get_2fa_status():
    with get_session() as db:
        result = db.execute(select(MFATOTP).where(MFATOTP.user_id == session['user_id']))
        mfa = result.scalar_one_or_none()
        
        if mfa:
            return jsonify({
                'enabled': mfa.is_enabled,
                'verified': mfa.is_verified,
                'last_used': mfa.last_used.isoformat() if mfa.last_used else None,
                'usage_count': mfa.usage_count
            })
        else:
            return jsonify({'enabled': False, 'verified': False})

@app.route('/api/import-passwords', methods=['POST'])
@csrf.exempt
@login_required
def import_passwords():
    try:
        data = request.get_json()
        passwords = data.get('passwords', [])
        
        if not passwords:
            return jsonify({'error': 'No passwords provided'}), 400
        
        imported_count = 0
        
        with get_session() as db:
            for pwd_data in passwords:
                # Validate required fields
                if not all(key in pwd_data for key in ['website_name', 'username', 'password']):
                    continue
                
                # Check if password already exists for this user and website
                existing = db.execute(
                    select(Password).where(
                        and_(
                            Password.user_id == session['user_id'],
                            Password.website_name == pwd_data['website_name']
                        )
                    )
                ).scalar_one_or_none()
                
                if existing:
                    # Update existing password
                    existing.encrypted_password = security.encrypt_password(pwd_data['password'])
                    existing.username = pwd_data['username']
                    existing.notes = pwd_data.get('notes', '')
                    existing.updated_at = datetime.utcnow()
                else:
                    # Create new password entry
                    new_password = Password(
                        user_id=session['user_id'],
                        website_name=pwd_data['website_name'],
                        username=pwd_data['username'],
                        encrypted_password=security.encrypt_password(pwd_data['password']),
                        notes=pwd_data.get('notes', '')
                    )
                    db.add(new_password)
                    imported_count += 1
            
            db.commit()
        
        return jsonify({
            'success': True,
            'imported_count': imported_count,
            'total_count': len(passwords)
        })
        
    except Exception as e:
        return jsonify({'error': f'Import failed: {str(e)}'}), 500

@app.route('/api/delete-account', methods=['POST'])
@csrf.exempt
@login_required
def delete_account():
    try:
        data = request.get_json()
        password = data.get('password')
        
        if not password:
            return jsonify({'error': 'Password is required'}), 400
        
        with get_session() as db:
            # Get user and verify password
            user = db.execute(select(User).where(User.id == session['user_id'])).scalar_one()
            
            if not security.verify_password(password, user.password_hash):
                return jsonify({'error': 'Invalid password'}), 400
            
            # Delete all user data
            # Delete passwords
            db.execute(delete(Password).where(Password.user_id == user.id))
            
            # Delete 2FA settings
            db.execute(delete(MFATOTP).where(MFATOTP.user_id == user.id))
            
            # Delete user account
            db.execute(delete(User).where(User.id == user.id))
            
            db.commit()
        
        # Clear session
        session.clear()
        
        return jsonify({'success': True, 'message': 'Account deleted successfully'})
        
    except Exception as e:
        return jsonify({'error': f'Failed to delete account: {str(e)}'}), 500

if __name__ == '__main__':
    # SECURITY: Never run with debug=True in production!
    DEBUG_MODE = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=DEBUG_MODE, host='0.0.0.0', port=5000)
