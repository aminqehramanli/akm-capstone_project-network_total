from flask_sqlalchemy import SQLAlchemy
from flask import Flask
import os

app = Flask(__name__)
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
    sha256_hash = db.Column(db.String(64), unique=True, nullable=False)
    file_metadata = db.Column(db.JSON)
    logs_path = db.Column(db.String(255))
    alerts_path = db.Column(db.String(255))

# Create Tables
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        print("Database initialized!")
