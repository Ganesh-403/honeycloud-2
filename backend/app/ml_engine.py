"""
AI/ML Threat Detection Engine
Uses Isolation Forest for anomaly detection
"""
import numpy as np
from sklearn.ensemble import IsolationForest
import logging

logger = logging.getLogger(__name__)

class MLThreatDetector:
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )
        self.is_trained = False
        logger.info("✅ ML Threat Detector initialized")
    
    def extract_features(self, attack_data: dict) -> np.array:
        """Extract numerical features from attack data"""
        features = []
        
        # Port mapping
        port_map = {'SSH': 22, 'FTP': 21, 'HTTP': 80}
        features.append(port_map.get(attack_data.get('service', 'SSH'), 0))
        
        # Text lengths
        features.append(len(attack_data.get('username', '')))
        features.append(len(attack_data.get('password', '')))
        
        # Time feature (hour of day)
        features.append(attack_data.get('hour', 12))
        
        return np.array(features).reshape(1, -1)
    
    def predict_threat(self, attack_data: dict) -> dict:
        """Predict threat level"""
        try:
            features = self.extract_features(attack_data)
            
            if not self.is_trained:
                # Train with dummy data first
                dummy_data = np.random.randn(100, 4)
                self.model.fit(dummy_data)
                self.is_trained = True
            
            prediction = self.model.predict(features)[0]
            score = abs(self.model.decision_function(features)[0])
            
            if prediction == -1:
                label = "malicious" if score > 0.5 else "anomaly"
            else:
                label = "benign"
            
            return {
                'label': label,
                'score': round(score, 3)
            }
        except Exception as e:
            logger.error(f"ML prediction error: {e}")
            return {'label': 'unknown', 'score': 0.0}
