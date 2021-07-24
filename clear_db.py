from config import db

db.users.delete_many({})
db.scans.delete_many({})
