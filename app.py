from flask import Flask, request, jsonify
from flask_cors import CORS
import smtplib
import random
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

app = Flask(__name__)

# ---- CONFIG ----
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', '*')  # set to your frontend domain in Render env vars
CORS(app, origins=ALLOWED_ORIGINS.split(',') if ALLOWED_ORIGINS != '*' else '*')

EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
FROM_EMAIL = os.getenv('FROM_EMAIL')
API_KEY = os.getenv('API_KEY')  # required for the delete endpoint

OTP_EXPIRY_MINUTES = 5
RESEND_COOLDOWN_SECONDS = 30
MAX_VERIFY_ATTEMPTS = 5

if not all([EMAIL_USER, EMAIL_PASS, FROM_EMAIL]):
    raise RuntimeError("Missing required env vars: EMAIL_USER, EMAIL_PASS, FROM_EMAIL")

otp_storage = {}
otp_attempts = {}
START_TIME = datetime.now()


def generate_otp():
    return str(random.randint(100000, 999999))


def send_email(to_email, subject, body):
    try:
        msg = MIMEMultipart()
        msg['From'] = FROM_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'html'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(EMAIL_USER, EMAIL_PASS)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Email error: {str(e)}")
        return False


def require_api_key(req):
    return bool(API_KEY) and req.headers.get('X-API-Key') == API_KEY


@app.route('/health', methods=['GET'])
def health():
    uptime_seconds = (datetime.now() - START_TIME).total_seconds()
    return jsonify({
        'status': 'ok',
        'service': 'otp-api',
        'timestamp': datetime.now().isoformat(),
        'uptime': str(timedelta(seconds=uptime_seconds)).split('.')[0],
        'active_otps': len(otp_storage)
    })


@app.route('/api/send-otp', methods=['POST'])
def send_otp():
    try:
        data = request.get_json(silent=True) or {}
        email = data.get('email', '').strip().lower()

        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        if '@' not in email or '.' not in email:
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400

        existing = otp_storage.get(email)
        if existing and existing.get('created', 0) > datetime.now().timestamp() - RESEND_COOLDOWN_SECONDS:
            return jsonify({'success': False, 'error': 'Please wait before requesting another OTP'}), 429

        otp = generate_otp()
        now_ts = datetime.now().timestamp()
        expiry = now_ts + OTP_EXPIRY_MINUTES * 60

        otp_storage[email] = {'otp': otp, 'expiry': expiry, 'created': now_ts}
        otp_attempts[email] = 0

        html_body = f"""
        <html>
            <body>
                <h2>Your OTP Code</h2>
                <p>Your verification code is:</p>
                <h1 style="color: #4CAF50; font-size: 32px;">{otp}</h1>
                <p>This OTP will expire in <b>{OTP_EXPIRY_MINUTES} minutes</b>.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </body>
        </html>
        """

        if not send_email(email, 'Your OTP Code', html_body):
            del otp_storage[email]
            otp_attempts.pop(email, None)
            return jsonify({'success': False, 'error': 'Failed to send email'}), 500

        return jsonify({
            'success': True,
            'message': 'OTP sent successfully',
            'data': {'email': email, 'expires_in': f'{OTP_EXPIRY_MINUTES} minutes'}
        })

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json(silent=True) or {}
        email = data.get('email', '').strip().lower()
        otp = data.get('otp', '').strip()

        if not email or not otp:
            return jsonify({'success': False, 'error': 'Email and OTP are required'}), 400

        stored_data = otp_storage.get(email)
        if not stored_data:
            return jsonify({'success': False, 'error': 'OTP not found'}), 404

        if datetime.now().timestamp() > stored_data['expiry']:
            del otp_storage[email]
            otp_attempts.pop(email, None)
            return jsonify({'success': False, 'error': 'OTP has expired'}), 400

        otp_attempts[email] = otp_attempts.get(email, 0) + 1
        if otp_attempts[email] > MAX_VERIFY_ATTEMPTS:
            del otp_storage[email]
            otp_attempts.pop(email, None)
            return jsonify({'success': False, 'error': 'Too many failed attempts, request a new OTP'}), 429

        if stored_data['otp'] == otp:
            del otp_storage[email]
            otp_attempts.pop(email, None)
            return jsonify({'success': True, 'message': 'OTP verified successfully'})

        return jsonify({'success': False, 'error': 'Invalid OTP'}), 400

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/delete-otp', methods=['DELETE'])
def delete_otp():
    if not require_api_key(request):
        return jsonify({'success': False, 'error': 'Unauthorized'}), 401
    try:
        data = request.get_json(silent=True) or {}
        email = data.get('email', '').strip().lower()

        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400

        deleted = otp_storage.pop(email, None)
        otp_attempts.pop(email, None)
        return jsonify({'success': True, 'message': 'OTP deleted' if deleted else 'No OTP found'})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.errorhandler(404)
def not_found(e):
    return jsonify({
        'success': False,
        'error': 'Endpoint not found',
        'endpoints': {
            'GET /health': 'Health check',
            'POST /api/send-otp': 'Send OTP',
            'POST /api/verify-otp': 'Verify OTP',
            'DELETE /api/delete-otp': 'Delete OTP (requires X-API-Key header)'
        }
    }), 404


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
