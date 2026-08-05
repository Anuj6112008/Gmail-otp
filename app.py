from flask import Flask, request, jsonify
from flask_cors import CORS
import smtplib
import random
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app)

otp_storage = {}
START_TIME = datetime.now()

EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
FROM_EMAIL = os.getenv('FROM_EMAIL')

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
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
            
        if '@' not in email or '.' not in email:
            return jsonify({'success': False, 'error': 'Invalid email format'}), 400
        
        otp = generate_otp()
        expiry = datetime.now() + timedelta(minutes=5)
        
        otp_storage[email] = {
            'otp': otp,
            'expiry': expiry.timestamp()
        }
        
        html_body = f"""
        <html>
            <body>
                <h2>Your OTP Code</h2>
                <p>Your verification code is:</p>
                <h1 style="color: #4CAF50; font-size: 32px;">{otp}</h1>
                <p>This OTP will expire in <b>5 minutes</b>.</p>
                <p>If you didn't request this, please ignore this email.</p>
            </body>
        </html>
        """
        
        email_sent = send_email(email, 'Your OTP Code', html_body)
        
        if not email_sent:
            return jsonify({'success': False, 'error': 'Failed to send email'}), 500
        
        return jsonify({
            'success': True,
            'message': 'OTP sent successfully',
            'data': {'email': email, 'expires_in': '5 minutes'}
        })
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        otp = data.get('otp', '').strip()
        
        if not email or not otp:
            return jsonify({'success': False, 'error': 'Email and OTP are required'}), 400
        
        stored_data = otp_storage.get(email)
        
        if not stored_data:
            return jsonify({'success': False, 'error': 'OTP not found'}), 404
        
        if datetime.now().timestamp() > stored_data['expiry']:
            del otp_storage[email]
            return jsonify({'success': False, 'error': 'OTP has expired'}), 400
        
        if stored_data['otp'] == otp:
            del otp_storage[email]
            return jsonify({'success': True, 'message': 'OTP verified successfully'})
        else:
            return jsonify({'success': False, 'error': 'Invalid OTP'}), 400
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/api/delete-otp', methods=['DELETE'])
def delete_otp():
    try:
        data = request.get_json()
        email = data.get('email', '').strip().lower()
        
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        deleted = otp_storage.pop(email, None)
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
            'DELETE /api/delete-otp': 'Delete OTP'
        }
    }), 404

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
