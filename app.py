
from flask import Flask, render_template, request, flash, redirect, url_for
from vapt import run_vulnerability_scans_and_pen_tests
from datetime import datetime
import logging

app = Flask(__name__)
app.secret_key = 'supersecretkey'  # Required for flashing messages
logging.basicConfig(level=logging.INFO)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    urls = request.form.get('urls')

    # Validate input
    if not urls:
        flash("Please provide at least one URL.", "error")
        return redirect(url_for('index'))

    # Clean and split input URLs
    url_list = [url.strip() for url in urls.splitlines() if url.strip()]
    
    # Check if the user provided any valid URLs
    if not url_list:
        flash("No valid URLs were provided.", "error")
        return redirect(url_for('index'))

    logging.info(f"Starting vulnerability scans for URLs: {url_list}")
    
    try:
        # Run vulnerability scans and penetration tests
        results = run_vulnerability_scans_and_pen_tests(url_list)
    except Exception as e:
        logging.error(f"Error during scans: {e}")
        flash("An error occurred while running the scans. Please try again.", "error")
        return redirect(url_for('index'))

    # Pass results to the report template
    return render_template('report.html', results=results, date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

if __name__ == '__main__':
    app.run(debug=True)
