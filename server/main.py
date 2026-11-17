from fastapi import FastAPI, Header, HTTPException, Depends, BackgroundTasks
from pydantic import BaseModel
from datetime import datetime
import sqlite3
import os
from dotenv import load_dotenv
import httpx

async def send_tg(alert_id: int, time_str: int, alert: AlertpayLoad):
    if not TG_TOKEN or not TG_CHAT_ID:
        return
    msg = (
        f"🚨 *NETGUARD ALERT #{alert_id} [{alert.severity}]*\n"
        f"• Sự kiện: `{alert.event_type}`\n"
        f"• Thời gian: `{time_str}`"
    )
    url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
    
    async with httpx.AsyncClient(timeout=5.0) as client:
        await client.post(url, json={
            "chat_id": TG_CHAT_ID,
            "text": msg,
            "parse_mode": "Markdown"
        })

load_dotenv()
API_key = os.getenv("NETGUARD_API_KEY", "netguard_lock_2508")
TG_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
TG_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID" , "")

DB_FILE = "netguard.db"

def ini_db():
    with sqlite3.connect(DB_FILE) as con:
        con.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER,
                time_str TEXT,
                event_type TEXT,
                severity TEXT,
                detail TEXT
            )
        """)
ini_db()

app = FastAPI(title = "Netguard SIEM")
API_key = "netguard_lock_2508"

def verify_api(x_api: str | None = Header(default = None)):
    if (x_api != API_key):
        raise HTTPException(status_code=401, detail="Unauthorized")

class AlertpayLoad(BaseModel):
    timestamp: int
    event_type: str
    severity: str
    detail: str

alert_db = []

@app.post("/api/alerts", dependencies=[Depends(verify_api)])

def receiveAlert(alert: AlertpayLoad, bg_tasks: BackgroundTasks):
    time_str = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
    # record = {
    #     "time": time_str,
    #     "event_type": alert.event_type,
    #     "severity": alert.severity,
    #     "detail": alert.detail
    # }
    # alert_db.append(record)
    with sqlite3.connect(DB_FILE) as con:
        cur = con.execute(
            "INSERT INTO alerts (timestamp, time_str, event_type, severity, detail) VALUES (?, ?, ?, ?, ?)",
            (alert.timestamp, time_str, alert.event_type, alert.severity, alert.detail)
        )
        alert_id = cur.lastrowid
    bg_tasks.add_task(send_tg, alert_id, time_str, alert)
    print(f"[{time_str}] [{alert.severity}] {alert.event_type} -> {alert.detail}")
    return {"status": "ok"}

@app.get("/api/alerts", dependencies=[Depends(verify_api)])
def list_alerts():
    with sqlite3.connect(DB_FILE) as con:
        con.row_factory = sqlite3.Row  
        rows = con.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50").fetchall()
        data = [dict(row) for row in rows]
    return {"total": len(data), "data": data}
