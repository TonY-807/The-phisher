import sqlite3
import datetime
import os

DB_NAME = "phishing.db"

def get_db_path():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base_dir, DB_NAME)

def init_db():
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    # Using IF NOT EXISTS to preserve data
    c.execute('''
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            input_data TEXT NOT NULL,
            input_type TEXT NOT NULL,
            classification TEXT NOT NULL,
            score INTEGER NOT NULL,
            scan_date TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def add_scan(input_data, input_type, classification, score):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute(
        "INSERT INTO scan_history (input_data, input_type, classification, score, scan_date) VALUES (?, ?, ?, ?, ?)",
        (input_data, input_type, classification, score, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    )
    conn.commit()
    conn.close()

def get_history(limit=50):
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    c.execute("SELECT id, input_data, input_type, classification, score, scan_date FROM scan_history ORDER BY id DESC LIMIT ?", (limit,))
    rows = c.fetchall()
    conn.close()
    
    history = []
    for row in rows:
        history.append({
            "id": row[0],
            "input_data": row[1],
            "input_type": row[2],
            "classification": row[3],
            "score": row[4],
            "scan_date": row[5]
        })
    return history

def get_stats():
    conn = sqlite3.connect(get_db_path())
    c = conn.cursor()
    
    stats = {}
    c.execute("SELECT COUNT(*) FROM scan_history")
    stats['total'] = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scan_history WHERE classification='Phishing'")
    stats['phishing'] = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scan_history WHERE classification='Suspicious'")
    stats['suspicious'] = c.fetchone()[0]
    
    c.execute("SELECT COUNT(*) FROM scan_history WHERE classification='Safe'")
    stats['safe'] = c.fetchone()[0]
    
    conn.close()
    return stats
