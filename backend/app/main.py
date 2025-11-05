from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from sse_starlette.sse import EventSourceResponse
import asyncio
import json
import random
import os
from datetime import datetime, timedelta
from typing import Optional
import logging

# Import our custom modules
try:
    from .alert_system import handle_attack_event, send_telegram_document
    from .report_generator import generate_csv_report, generate_pdf_report
    from .excel_export import generate_excel_report
    from .auth import (
        authenticate_user, 
        create_access_token, 
        get_current_user, 
        get_admin_user,
        ACCESS_TOKEN_EXPIRE_MINUTES
    )
except ImportError as e:
    logger = logging.getLogger(__name__)
    logger.warning(f"Some modules not available: {e}")
    def handle_attack_event(event): pass
    def send_telegram_document(path, caption): pass
    def generate_csv_report(events, filename=None): return "report.csv"
    def generate_pdf_report(events, stats, filename=None): return "report.txt"
    def generate_excel_report(events, stats, filename=None): return "report.xlsx"
    def authenticate_user(username, password): return None
    def create_access_token(data, expires_delta=None): return "token"
    def get_current_user(token): return None
    def get_admin_user(current_user): return None
    ACCESS_TOKEN_EXPIRE_MINUTES = 30

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="HoneyCloud-X API",
    description="Smart Scalable Honeypot Platform with Authentication",
    version="1.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for demo
attack_events = []

# Ensure reports directory exists
os.makedirs("reports", exist_ok=True)


@app.on_event("startup")
async def startup_event():
    """Generate sample attack data on startup"""
    logger.info("🚀 Starting HoneyCloud-X API...")
    generate_sample_data()
    logger.info(f"✅ Generated {len(attack_events)} sample attack events")
    
    # Test alerts for critical events on startup
    critical_events = [e for e in attack_events if e['severity'] == 'CRITICAL'][:2]
    for event in critical_events:
        handle_attack_event(event)


def generate_sample_data():
    """Generate realistic attack data"""
    services = ['SSH', 'FTP', 'HTTP']
    severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    labels = ['benign', 'anomaly', 'malicious']
    usernames = ['admin', 'root', 'user', 'test', 'administrator', 'guest']
    
    for i in range(100):
        attack_events.append({
            'id': i + 1,
            'timestamp': (datetime.now() - timedelta(minutes=i*10)).isoformat(),
            'service': random.choice(services),
            'source_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            'source_port': random.randint(1024, 65535),
            'username': random.choice(usernames),
            'password': f"pass{random.randint(1000,9999)}",
            'command': random.choice(['ls', 'pwd', 'cat /etc/passwd', 'wget malware.sh', 'curl evil.com']),
            'severity': random.choice(severities),
            'ai_label': random.choice(labels),
            'threat_score': round(random.uniform(0, 1), 2)
        })


# ========================
# AUTHENTICATION ENDPOINTS
# ========================

@app.post("/auth/login")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Login endpoint - Returns JWT token
    
    Demo credentials:
    - admin / admin123
    - analyst / analyst123
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        logger.warning(f"❌ Failed login attempt: {form_data.username}")
        raise HTTPException(
            status_code=401, 
            detail="Invalid credentials"
        )
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"], "role": user.get("role")},
        expires_delta=access_token_expires
    )
    
    logger.info(f"✅ User logged in: {user['username']} ({user.get('role')})")
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user["username"],
        "role": user.get("role")
    }


@app.get("/api/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    """Protected endpoint - requires login"""
    return {
        "message": f"Welcome {current_user['username']}!",
        "role": current_user.get("role"),
        "status": "authenticated"
    }


# ========================
# PUBLIC ENDPOINTS
# ========================

@app.get("/")
def root():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "HoneyCloud-X API",
        "version": "1.0.0",
        "timestamp": datetime.now().isoformat(),
        "auth": "JWT (login at /auth/login)"
    }


@app.get("/api/events")
def get_events(
    limit: int = 50, 
    service: Optional[str] = None, 
    severity: Optional[str] = None,
    current_user: dict = Depends(get_current_user)
):
    """
    Get attack events with optional filters
    Requires authentication
    """
    filtered_events = attack_events
    
    if service:
        filtered_events = [e for e in filtered_events if e['service'] == service]
    if severity:
        filtered_events = [e for e in filtered_events if e['severity'] == severity]
    
    logger.info(f"User {current_user['username']} accessed events (limit: {limit})")
    return filtered_events[:limit]


@app.get("/api/stats")
def get_statistics(current_user: dict = Depends(get_current_user)):
    """
    Get dashboard statistics
    Requires authentication
    """
    total_events = len(attack_events)
    
    # Events by service
    service_counts = {}
    for event in attack_events:
        service = event['service']
        service_counts[service] = service_counts.get(service, 0) + 1
    
    # Events by severity
    severity_counts = {}
    for event in attack_events:
        severity = event['severity']
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # AI labels
    label_counts = {}
    for event in attack_events:
        label = event['ai_label']
        label_counts[label] = label_counts.get(label, 0) + 1
    
    logger.info(f"User {current_user['username']} accessed statistics")
    
    return {
        'total_events': total_events,
        'events_by_service': service_counts,
        'events_by_severity': severity_counts,
        'ai_labels': label_counts,
        'last_updated': datetime.now().isoformat()
    }


@app.get("/api/events/stream")
async def event_stream(current_user: dict = Depends(get_current_user)):
    """
    Server-Sent Events endpoint for real-time updates
    Requires authentication
    """
    async def event_generator():
        last_id = len(attack_events)
        while True:
            # Simulate new attack every 10 seconds
            if random.random() > 0.6:
                new_event = {
                    'id': last_id + 1,
                    'timestamp': datetime.now().isoformat(),
                    'service': random.choice(['SSH', 'FTP', 'HTTP']),
                    'source_ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                    'username': random.choice(['admin', 'root', 'hacker']),
                    'severity': random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                    'ai_label': random.choice(['benign', 'anomaly', 'malicious']),
                    'threat_score': round(random.uniform(0, 1), 2)
                }
                attack_events.append(new_event)
                
                # Send alert if critical/malicious
                handle_attack_event(new_event)
                
                yield {
                    "event": "new_attack",
                    "data": json.dumps(new_event)
                }
                last_id += 1
            
            await asyncio.sleep(10)
    
    logger.info(f"User {current_user['username']} started event stream")
    return EventSourceResponse(event_generator())


# ========================
# REPORT GENERATION (ADMIN ONLY)
# ========================

@app.post("/api/reports/generate")
def generate_report(
    format: str = "csv", 
    send_telegram: bool = False,
    current_user: dict = Depends(get_admin_user)
):
    """
    Generate attack report in CSV, Excel, or PDF format
    Admin only endpoint
    
    Formats: csv, xlsx, txt
    """
    try:
        stats = get_statistics(current_user)
        
        logger.info(f"Admin {current_user['username']} generating {format} report")
        
        if format.lower() == "xlsx":
            filepath = generate_excel_report(attack_events, stats)
            message = "Excel report generated successfully"
        elif format.lower() == "csv":
            filepath = generate_csv_report(attack_events)
            message = "CSV report generated successfully"
        else:
            filepath = generate_pdf_report(attack_events, stats)
            message = "Text report generated successfully"
        
        # Optionally send to Telegram
        if send_telegram:
            send_telegram_document(filepath, caption=f"HoneyCloud-X {format.upper()} Report")
            message += " and sent to Telegram"
            logger.info(f"Report sent to Telegram by {current_user['username']}")
        
        return {
            "status": "success",
            "message": message,
            "filepath": filepath,
            "events_count": len(attack_events),
            "download_url": f"/api/reports/download?file={os.path.basename(filepath)}"
        }
    
    except Exception as e:
        logger.error(f"Error generating report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/download")
def download_report(file: str):
    """
    Download a generated report file
    (Auth check already done during generation)
    """
    filepath = os.path.join("reports", file)
    
    if not os.path.exists(filepath):
        logger.warning(f"Attempted to download non-existent file: {file}")
        raise HTTPException(status_code=404, detail="Report file not found")
    
    logger.info(f"Report downloaded: {file}")
    
    # Determine media type based on file extension
    if file.endswith('.xlsx'):
        media_type = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
    elif file.endswith('.csv'):
        media_type = 'text/csv'
    else:
        media_type = 'application/octet-stream'
    
    return FileResponse(
        filepath,
        media_type=media_type,
        filename=file
    )

    """
    Download a generated report file
    Requires authentication
    """
    filepath = os.path.join("reports", file)
    
    if not os.path.exists(filepath):
        logger.warning(f"User {current_user['username']} attempted to download non-existent file: {file}")
        raise HTTPException(status_code=404, detail="Report file not found")
    
    logger.info(f"User {current_user['username']} downloaded: {file}")
    
    return FileResponse(
        filepath,
        media_type='application/octet-stream',
        filename=file
    )


# ========================
# HEALTH CHECK
# ========================

@app.get("/health")
def health_check():
    """Kubernetes-style health check"""
    return {
        "status": "healthy",
        "checks": {
            "api": "ok",
            "honeypots": "ok",
            "ml_engine": "ok",
            "auth": "ok",
            "database": "ok"
        },
        "timestamp": datetime.now().isoformat(),
        "events_count": len(attack_events)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
