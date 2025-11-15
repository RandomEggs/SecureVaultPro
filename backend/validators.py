"""
Input validation and sanitization utilities
Prevents XSS, injection attacks, and ensures data integrity
"""
import re
from email_validator import validate_email, EmailNotValidError
from markupsafe import escape

class ValidationError(Exception):
    """Custom exception for validation errors"""
    pass

def validate_email_format(email: str) -> tuple[bool, str]:
    """
    Validate email format using email-validator library
    Returns: (is_valid, error_message)
    """
    if not email or not email.strip():
        return False, "Email is required"
    
    try:
        # Validate and normalize email
        valid = validate_email(email.strip(), check_deliverability=False)
        return True, ""
    except EmailNotValidError as e:
        return False, str(e)

def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Validate password meets security requirements
    Requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one number
    - At least one special character
    Returns: (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 8:
        return False, "Password must be at least 8 characters long"
    
    if len(password) > 128:
        return False, "Password must be less than 128 characters"
    
    if not re.search(r'[A-Z]', password):
        return False, "Password must contain at least one uppercase letter"
    
    if not re.search(r'[a-z]', password):
        return False, "Password must contain at least one lowercase letter"
    
    if not re.search(r'[0-9]', password):
        return False, "Password must contain at least one number"
    
    if not re.search(r'[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\\/]', password):
        return False, "Password must contain at least one special character"
    
    # Check for common weak passwords
    common_passwords = ['password', 'Password123!', 'Welcome123!', 'Admin123!']
    if password in common_passwords:
        return False, "This password is too common. Please choose a different one"
    
    return True, ""

def sanitize_string(input_str: str, max_length: int = 255) -> str:
    """
    Sanitize string input to prevent XSS and injection attacks
    - Strips whitespace
    - Escapes HTML
    - Limits length
    Returns: sanitized string
    """
    if not input_str:
        return ""
    
    # Strip whitespace
    sanitized = input_str.strip()
    
    # Limit length
    sanitized = sanitized[:max_length]
    
    # Escape HTML to prevent XSS
    sanitized = escape(sanitized)
    
    return str(sanitized)

def validate_website_name(website_name: str) -> tuple[bool, str]:
    """
    Validate website/service name
    Returns: (is_valid, error_message)
    """
    if not website_name or not website_name.strip():
        return False, "Website name is required"
    
    # Remove leading/trailing whitespace
    cleaned = website_name.strip()
    
    if len(cleaned) < 1:
        return False, "Website name cannot be empty"
    
    if len(cleaned) > 255:
        return False, "Website name must be less than 255 characters"
    
    # Check for SQL injection patterns
    sql_patterns = [
        r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|EXECUTE)\b)",
        r"(--|;|\/\*|\*\/|xp_|sp_)",
        r"(\bunion\b.*\bselect\b)",
    ]
    
    for pattern in sql_patterns:
        if re.search(pattern, cleaned, re.IGNORECASE):
            return False, "Website name contains invalid characters"
    
    return True, ""

def validate_username_field(username: str) -> tuple[bool, str]:
    """
    Validate username/login field
    Returns: (is_valid, error_message)
    """
    if not username or not username.strip():
        return False, "Username is required"
    
    cleaned = username.strip()
    
    if len(cleaned) < 1:
        return False, "Username cannot be empty"
    
    if len(cleaned) > 255:
        return False, "Username must be less than 255 characters"
    
    return True, ""

def validate_token(token: str) -> tuple[bool, str]:
    """
    Validate verification/reset tokens
    Returns: (is_valid, error_message)
    """
    if not token or not token.strip():
        return False, "Token is required"
    
    # Tokens should be alphanumeric only
    if not re.match(r'^[a-zA-Z0-9]+$', token):
        return False, "Invalid token format"
    
    # Check length (32 characters expected)
    if len(token) != 32:
        return False, "Invalid token length"
    
    return True, ""

def validate_2fa_code(code: str) -> tuple[bool, str]:
    """
    Validate 2FA TOTP code
    Returns: (is_valid, error_message)
    """
    if not code or not code.strip():
        return False, "Verification code is required"
    
    cleaned = code.strip()
    
    # TOTP codes are 6 digits
    if not re.match(r'^\d{6}$', cleaned):
        return False, "Verification code must be 6 digits"
    
    return True, ""

def validate_backup_code(code: str) -> tuple[bool, str]:
    """
    Validate 2FA backup code
    Returns: (is_valid, error_message)
    """
    if not code or not code.strip():
        return False, "Backup code is required"
    
    cleaned = code.strip().upper()
    
    # Backup codes are 8 characters (alphanumeric)
    if not re.match(r'^[A-Z0-9]{8}$', cleaned):
        return False, "Backup code must be 8 alphanumeric characters"
    
    return True, ""
