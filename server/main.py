from fastapi import FastAPI, Header, HTTPException, Depends
from pydantic import BaseModel
from datetime import datetime

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
def receiveAlert(alert: AlertpayLoad):
    time_str = datetime.fromtimestamp(alert.timestamp).strftime('%Y-%m-%d %H:%M:%S')
    record = {
        "time": time_str,
        "event_type": alert.event_type,
        "severity": alert.severity,
        "detail": alert.detail
    }
    alert_db.append(record)
    print(f"[{time_str}] [{alert.severity}] {alert.event_type} -> {alert.detail}")
    return {"status": "ok"}

@app.get("/api/alerts", dependencies=[Depends(verify_api)])
def list_alerts():
    return {"total": len(alert_db), "data": alert_db}
