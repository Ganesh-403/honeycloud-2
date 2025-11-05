import random
from datetime import datetime, timedelta
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, AttackEvent

# Generate 100 synthetic attack events
def generate_sample_data(db_url="sqlite:///./honeycloud.db"):
    engine = create_engine(db_url)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    services = ['ssh', 'ftp', 'http']
    usernames = ['admin', 'root', 'user', 'test', 'administrator']
    severities = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    ai_labels = ['benign', 'anomaly', 'malicious']
    
    events = []
    base_time = datetime.now() - timedelta(days=7)
    
    for i in range(100):
        event = AttackEvent(
            timestamp=base_time + timedelta(minutes=random.randint(0, 10080)),
            service=random.choice(services),
            source_ip=f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
            source_port=random.randint(1024, 65535),
            username=random.choice(usernames),
            password=f"pass{random.randint(1000,9999)}",
            command=random.choice(['ls', 'whoami', 'cat /etc/passwd', 'wget malware.sh']),
            severity=random.choice(severities),
            ai_label=random.choice(ai_labels),
            threat_score=round(random.uniform(0, 1), 3)
        )
        events.append(event)
    
    session.add_all(events)
    session.commit()
    print(f"✅ Generated {len(events)} sample attack events")
    session.close()

if __name__ == "__main__":
    generate_sample_data()
