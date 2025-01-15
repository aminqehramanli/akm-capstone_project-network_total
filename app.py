from flask import Flask, render_template, request, send_from_directory, jsonify
from flask_sqlalchemy import SQLAlchemy
import os
import hashlib
import shutil
import json
import zipfile
from datetime import datetime
import subprocess

app = Flask(__name__)
db_user = os.getenv('DB_USER', 'default_user')
db_password = os.getenv('DB_PASSWORD', 'default_password')
db_host = os.getenv('DB_HOST', 'localhost')
db_name = os.getenv('DB_NAME', 'pcap_db')
app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@{db_host}/{db_name}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# Table Model
class PcapFile(db.Model):
    __tablename__ = 'pcap_files'
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    md5_hash = db.Column(db.String(32), unique=True, nullable=False)
    sha256_hash = db.Column(db.String(64), unique=False, nullable=False)
    file_metadata = db.Column(db.JSON)
    logs_path = db.Column(db.String(255))
    alerts_path = db.Column(db.String(255))

# Function to generate MD5 hash of the file
def generate_md5(filename):
    """Generate MD5 hash of a filename.

    Args:
        filename (string): Name of the file.

    Returns:
        string: MD5 hash of the filename.
    """    
    md5_hash = hashlib.md5()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
    return md5_hash.hexdigest()

def generate_sha256(filename):
    """Generate SHA256 hash of a filename.

    Args:
        filename (string): Name of the file.

    Returns:
        string: SHA256 hash of the filename.
    """    
    sha256_hash = hashlib.sha256()
    with open(filename, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

# Function to parse Suricata alerts (new-line delimited JSON)
def parse_suricata_alerts(alerts_file_path):
    """Parse Suricata alerts from a file.

    Args:
        alerts_file_path (string): local file path to the alerts file.

    Returns:
        list: List of alert dictionaries.
    """    
    alerts = []
    try:
        with open(alerts_file_path, 'r') as f:
            for line in f:
                try:
                    alert = json.loads(line)
                    alerts.append(alert)
                except json.JSONDecodeError as e:
                    print(f"Error decoding JSON line: {line} - {e}")
    except FileNotFoundError:
        print(f"File not found: {alerts_file_path}")
    except Exception as e:
        print(f"Error reading file: {e}")
    return alerts

# Function to analyze PCAP using the engine (Suricata and Zeek)
def analyze_pcap_with_engine(pcap_file_path, output_dir):
    """
    Analyze a PCAP file using Suricata and Zeek.
    
    Args:
    - pcap_file_path (str): Path to the PCAP file.
    - output_dir (str): Directory to store the results (logs and alerts).
    
    Returns:
    - result (dict): Dictionary containing the file paths to the output logs and alerts.
    """
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    result = {}
    
    # Generate MD5 hash of the PCAP file for unique filenames
    pcap_md5 = generate_md5(pcap_file_path)
    
    # Set directories for output files
    suricata_output_dir = os.path.join(output_dir, "alerts")
    os.makedirs(suricata_output_dir, exist_ok=True)
    
    # Suricata command to run the analysis
    try:
        subprocess.run(
            ['suricata', '-r', pcap_file_path, '-l', suricata_output_dir],
            check=True
        )
        
        # Save the Suricata output with MD5 as filename
        suricata_output_file = os.path.join(suricata_output_dir, f"{pcap_md5}.json")
        shutil.move(os.path.join(suricata_output_dir, 'eve.json'), suricata_output_file)
        result['suricata_logs'] = suricata_output_file
    except subprocess.CalledProcessError as e:
        print(f"Error running Suricata: {e}")
    
    # Zeek command to run the analysis
    zeek_output_dir = os.path.join(output_dir, "logs", pcap_md5)
    os.makedirs(zeek_output_dir, exist_ok=True)
    
    try:
        subprocess.run(
            ['/usr/local/zeek/bin/zeek', '-r', pcap_file_path],
            check=True
        )
        
        # Move all Zeek log files to the MD5-named directory
        for f in os.listdir():
            if f.endswith('.log'):
                shutil.move(f, os.path.join(zeek_output_dir, f))
        
        # Create a zip of the Zeek output directory
        zeek_zip_path = os.path.join(output_dir, "logs", f"{pcap_md5}.zip")
        with zipfile.ZipFile(zeek_zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for foldername, subfolders, filenames in os.walk(zeek_output_dir):
                for filename in filenames:
                    zipf.write(os.path.join(foldername, filename), os.path.relpath(os.path.join(foldername, filename), zeek_output_dir))
        
        result['zeek_logs'] = zeek_zip_path
    except subprocess.CalledProcessError as e:
        print(f"Error running Zeek: {e}")
    
    return result

# Route to handle file upload and analysis
@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' in request.files and request.files['file']:
            file = request.files['file']
            filename = file.filename
            pcap_file_path = os.path.join('uploads', filename)
            file.save(pcap_file_path)

            # Generate hash for the uploaded PCAP file
            pcap_md5 = generate_md5(pcap_file_path)
            pcap_sha256 = generate_sha256(pcap_file_path)

            # Check if file already exists in the database
            existing_pcap = PcapFile.query.filter_by(md5_hash=pcap_md5).first()
            if existing_pcap:
                alerts_file = existing_pcap.alerts_path
                zip_file = existing_pcap.logs_path
                alerts_data = parse_suricata_alerts(alerts_file)
                return render_template('alerts.html', alerts_data=alerts_data, zip_file=zip_file)

            # File not found, analyze with engine
            output_dir = 'output'
            analysis_result = analyze_pcap_with_engine(pcap_file_path, output_dir)
            
            # Save results to the database
            new_pcap = PcapFile(
                filename=filename,
                md5_hash=pcap_md5,
                sha256_hash=pcap_sha256,  # Add proper hash calculation if needed
                file_metadata={'timestamp': datetime.now().isoformat()},
                logs_path=analysis_result['zeek_logs'],
                alerts_path=analysis_result['suricata_logs']
            )
            db.session.add(new_pcap)
            db.session.commit()

            # Send the results back to the front-end
            alerts_data = parse_suricata_alerts(analysis_result['suricata_logs'])
            return render_template('alerts.html', alerts_data=alerts_data, zip_file=analysis_result['zeek_logs'])

        hash_value = request.form.get('hash_value')
        if hash_value:
            hash_value = str(hash_value).lower()
            # Search for the hash in the database (MD5 or SHA256)
            existing_pcap = PcapFile.query.filter(
                (PcapFile.md5_hash == hash_value) | (PcapFile.sha256_hash == hash_value)
            ).first()
            if existing_pcap:
                alerts_file = existing_pcap.alerts_path
                zip_file = existing_pcap.logs_path
                alerts_data = parse_suricata_alerts(alerts_file)
                return render_template('alerts.html', alerts_data=alerts_data, zip_file=zip_file)

            # If not found, return an error message or redirect
            return render_template('error.html', message="Hash not found in the database.")

    return render_template('index.html')

# Route to download the ZIP file generated by Zeek
@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory('output/logs', filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(host="192.168.40.55", port=5000, debug=True)
