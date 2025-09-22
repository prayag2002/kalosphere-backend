#!/usr/bin/env python3
"""
Test script for Kalosphere Auth Service API
This script demonstrates the main authentication features.
"""

import requests
import json
import time

BASE_URL = "http://127.0.0.1:8000/api/auth"

def cleanup_test_user():
    """Clean up any existing test user"""
    print("🧹 Cleaning up any existing test user...")
    import os
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_service.settings')
    django.setup()
    
    from users.models import User
    try:
        user = User.objects.get(email="test@kalosphere.com")
        user.delete()
        print("✅ Existing test user cleaned up")
    except User.DoesNotExist:
        print("ℹ️ No existing test user found")

def test_register():
    """Test user registration"""
    print("🔐 Testing User Registration...")
    
    data = {
        "email": "test@kalosphere.com",
        "username": "testuser",
        "password": "testpass123"
    }
    
    response = requests.post(f"{BASE_URL}/register/", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code == 201

def verify_email_manually():
    """Manually verify email for testing"""
    print("📧 Manually verifying email for testing...")
    
    # In a real scenario, this would be done via the email link
    # For testing, we'll use the admin interface or direct database update
    import os
    import django
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'auth_service.settings')
    django.setup()
    
    from users.models import User
    try:
        user = User.objects.get(email="test@kalosphere.com")
        user.is_email_verified = True
        user.save()
        print("✅ Email verified manually for testing")
        return True
    except User.DoesNotExist:
        print("❌ User not found")
        return False

def test_login():
    """Test user login"""
    print("\n🔑 Testing User Login...")
    
    data = {
        "email": "test@kalosphere.com",
        "password": "testpass123"
    }
    
    response = requests.post(f"{BASE_URL}/login/", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    
    if response.status_code == 200:
        return response.json().get("access")
    return None

def test_profile(access_token):
    """Test getting user profile"""
    print("\n👤 Testing User Profile...")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{BASE_URL}/profile/", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code == 200

def test_change_password(access_token):
    """Test changing password"""
    print("\n🔒 Testing Password Change...")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    data = {
        "current_password": "testpass123",
        "new_password": "newpass123",
        "confirm_password": "newpass123"
    }
    
    response = requests.post(f"{BASE_URL}/change-password/", json=data, headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code == 200

def test_forgot_password():
    """Test forgot password"""
    print("\n📧 Testing Forgot Password...")
    
    data = {"email": "test@kalosphere.com"}
    response = requests.post(f"{BASE_URL}/forgot-password/", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code == 200

def test_totp_setup(access_token):
    """Test TOTP setup"""
    print("\n🔐 Testing TOTP Setup...")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.get(f"{BASE_URL}/mfa/totp/setup/", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code == 200

def test_email_mfa_setup(access_token):
    """Test email MFA setup"""
    print("\n📧 Testing Email MFA Setup...")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    response = requests.post(f"{BASE_URL}/mfa/email/setup/", headers=headers)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.json()}")
    return response.status_code == 200

def test_brute_force_protection():
    """Test brute force protection"""
    print("\n🛡️ Testing Brute Force Protection...")
    
    data = {
        "email": "test@kalosphere.com",
        "password": "wrongpassword"
    }
    
    for i in range(6):  # Try 6 times to trigger lockout
        response = requests.post(f"{BASE_URL}/login/", json=data)
        print(f"Attempt {i+1}: Status {response.status_code}")
        if response.status_code == 423:  # Account locked
            print("✅ Account locked after multiple failed attempts!")
            return True
    
    return False

def main():
    """Run all tests"""
    print("🚀 Starting Kalosphere Auth Service API Tests\n")
    
    # Clean up any existing test user
    cleanup_test_user()
    
    # Test basic authentication
    if not test_register():
        print("❌ Registration failed")
        return
    
    # Manually verify email for testing
    print("\n⏳ Verifying email for testing...")
    if not verify_email_manually():
        print("❌ Email verification failed")
        return
    
    # Test login
    access_token = test_login()
    if not access_token:
        print("❌ Login failed")
        return
    
    # Test profile
    if not test_profile(access_token):
        print("❌ Profile access failed")
        return
    
    # Test password change
    if not test_change_password(access_token):
        print("❌ Password change failed")
        return
    
    # Test forgot password
    if not test_forgot_password():
        print("❌ Forgot password failed")
        return
    
    # Test MFA features
    if not test_totp_setup(access_token):
        print("❌ TOTP setup failed")
        return
    
    if not test_email_mfa_setup(access_token):
        print("❌ Email MFA setup failed")
        return
    
    # Test brute force protection
    if not test_brute_force_protection():
        print("❌ Brute force protection test failed")
        return
    
    print("\n✅ All tests completed successfully!")
    print("\n🎉 Kalosphere Auth Service is working properly!")

if __name__ == "__main__":
    main()
