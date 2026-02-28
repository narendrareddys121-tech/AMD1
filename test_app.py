import pytest
import os
import json
from app import app
from models import get_db

@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False
    
    with app.test_client() as client:
        with app.app_context():
            yield client

def test_index_route(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b"PhishShield AI" in response.data

def test_api_session(client):
    response = client.get('/api/session')
    assert response.status_code == 401
    
def test_login_invalid(client):
    response = client.post('/api/login', json={'email': 'wrong@test.com', 'password': 'wrong'})
    assert response.status_code == 401
    assert b"Invalid email or password" in response.data

def test_resources_api(client):
    response = client.get('/api/resources')
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'resources' in data
    assert len(data['resources']) > 0
    
def test_detection_engine():
    from detection_engine import analyze_message
    
    # Test a safe message
    safe_result = analyze_message("Hi Mom, how are you doing today? Let's get coffee later.")
    assert safe_result['risk_level'] == 'safe'
    
    # Test a phishing message
    phishing_result = analyze_message("URGENT: Your account will be suspended! Click here http://bit.ly/suspend to verify your password immediately.")
    assert phishing_result['risk_level'] in ['suspicious', 'high_risk']
    assert phishing_result['risk_score'] > 33
