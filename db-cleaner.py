from app import *

from app import PcapFile  # Import the model

# Delete all rows from all tables
with app.app_context():
    db.session.query(PcapFile).delete()  # Clear the `PcapFile` table
    db.session.commit()
    print("All entries in the database have been deleted.")
