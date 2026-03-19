from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import analyzer
import email_analyzer
import database
import pdf_generator
import os

app = Flask(__name__)
app.secret_key = 'super_secret_key_for_flash_messages'

# Initialize database
database.init_db()

@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/dashboard')
def dashboard():
    stats = database.get_stats()
    history = database.get_history(limit=5)
    return render_template('dashboard.html', stats=stats, history=history)

@app.route('/url', methods=['GET', 'POST'])
def url_analysis():
    result = None
    if request.method == 'POST':
        url = request.form.get('url')
        if not url:
            flash('Please enter a URL to scan.', 'danger')
            return redirect(url_for('url_analysis'))
            
        result = analyzer.calculate_risk_score(url)
        database.add_scan(result['url'], 'URL', result['classification'], result['score'])
        
    return render_template('url_scan.html', result=result)

@app.route('/email', methods=['GET', 'POST'])
def email_analysis():
    result = None
    if request.method == 'POST':
        email_content = request.form.get('email_content')
        if not email_content:
            flash('Please paste email content to scan.', 'danger')
            return redirect(url_for('email_analysis'))
            
        result = email_analyzer.analyze_email_text(email_content)
        database.add_scan(result['input_data'], 'Email', result['classification'], result['score'])
        
    return render_template('email_scan.html', result=result)

@app.route('/logs')
def logs():
    history = database.get_history(limit=100)
    return render_template('logs.html', history=history)

@app.route('/download_report', methods=['POST'])
def download_report():
    input_data = request.form.get('input_data')
    input_type = request.form.get('input_type', 'URL')
    
    if not input_data:
        flash('Invalid request for report generation.', 'danger')
        return redirect(url_for('dashboard'))
    
    if input_type == 'Email':
        result = email_analyzer.analyze_email_text(input_data)
    else:
        result = analyzer.calculate_risk_score(input_data)
    
    pdf_path = pdf_generator.generate_phishing_report(result)
    return send_file(pdf_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
