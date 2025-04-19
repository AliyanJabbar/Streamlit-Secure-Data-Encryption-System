# import streamlit as st
# import hashlib
# from cryptography.fernet import Fernet

# # Generate a key (this should be stored securely in production)
# KEY = Fernet.generate_key()
# cipher = Fernet(KEY)

# # In-memory data storage
# stored_data = {}  # {"user1_data": {"encrypted_text": "xyz", "passkey": "hashed"}}
# failed_attempts = 0

# # Function to hash passkey
# def hash_passkey(passkey):
#     return hashlib.sha256(passkey.encode()).hexdigest()


# # Function to encrypt data
# def encrypt_data(text, passkey):
#     return cipher.encrypt(text.encode()).decode()


# # Function to decrypt data
# def decrypt_data(encrypted_text, passkey):
#     global failed_attempts
#     hashed_passkey = hash_passkey(passkey)

#     for key, value in stored_data.items():
#         if (
#             value["encrypted_text"] == encrypted_text
#             and value["passkey"] == hashed_passkey
#         ):
#             failed_attempts = 0
#             return cipher.decrypt(encrypted_text.encode()).decode()

#     failed_attempts += 1
#     return None


# # Streamlit UI
# st.title("🔒 Secure Data Encryption System")

# # Navigation
# menu = ["Home", "Store Data", "Retrieve Data", "Login"]
# choice = st.sidebar.selectbox("Navigation", menu)

# if choice == "Home":
#     st.subheader("🏠 Welcome to the Secure Data System")
#     st.write(
#         "Use this app to **securely store and retrieve data** using unique passkeys."
#     )

# elif choice == "Store Data":
#     st.subheader("📂 Store Data Securely")
#     user_data = st.text_area("Enter Data:")
#     passkey = st.text_input("Enter Passkey:", type="password")

#     # storing data in memory
#     if st.button("Encrypt & Save"):
#         if user_data and passkey:
#             hashed_passkey = hash_passkey(passkey)
#             encrypted_text = encrypt_data(user_data, passkey)
#             stored_data[encrypted_text] = {
#                 "encrypted_text": encrypted_text,
#                 "passkey": hashed_passkey,
#             }
#             st.success("✅ Data stored securely!")
#             st.success(f"your data: {stored_data[encrypted_text]}")
#             print(f"your data: {stored_data[encrypted_text]}")
#         else:
#             st.error("⚠️ Both fields are required!")

# elif choice == "Retrieve Data":
#     st.subheader("🔍 Retrieve Your Data")
#     encrypted_text = st.text_area("Enter Encrypted Data:")
#     passkey = st.text_input("Enter Passkey:", type="password")

#     if st.button("Decrypt"):
#         if encrypted_text and passkey:
#             decrypted_text = decrypt_data(encrypted_text, passkey)

#             if decrypted_text:
#                 st.success(f"✅ Decrypted Data: {decrypted_text}")
#             else:
#                 st.error(
#                     f"❌ Incorrect passkey! Attempts remaining: {3 - failed_attempts}"
#                 )

#                 if failed_attempts >= 3:
#                     st.warning(
#                         "🔒 Too many failed attempts! Redirecting to Login Page."
#                     )
#                     st.experimental_rerun()
#         else:
#             st.error("⚠️ Both fields are required!")

# elif choice == "Login":
#     st.subheader("🔑 Reauthorization Required")
#     login_pass = st.text_input("Enter Master Password:", type="password")

#     if st.button("Login"):
#         if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
#             # global failed_attempts
#             failed_attempts = 0
#             st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
#             st.experimental_rerun()
#         else:
#             st.error("❌ Incorrect password!")


import streamlit as st
import hashlib
import os
import json
from cryptography.fernet import Fernet

# Initialize session state for persistent storage across reruns
if "stored_data" not in st.session_state:
    st.session_state.stored_data = {}
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

# Generate or load a persistent key
KEY_FILE = "encryption_key.key"
if os.path.exists(KEY_FILE):
    with open(KEY_FILE, "rb") as key_file:
        KEY = key_file.read()
else:
    KEY = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(KEY)

cipher = Fernet(KEY)


# Function to hash passkey
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()


# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)

    for key, value in st.session_state.stored_data.items():
        if (
            value["encrypted_text"] == encrypted_text
            and value["passkey"] == hashed_passkey
        ):
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()

    st.session_state.failed_attempts += 1
    return None


# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write(
        "Use this app to **securely store and retrieve data** using unique passkeys."
    )

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    # storing data in session state
    if st.button("Encrypt & Save"):
        if user_data and passkey:
            hashed_passkey = hash_passkey(passkey)
            encrypted_text = encrypt_data(user_data, passkey)
            st.session_state.stored_data[encrypted_text] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
            }
            st.success("✅ Data stored securely!")

            # Display the encrypted text for the user to copy
            st.info("**Save this encrypted text to retrieve your data later:**")
            st.code(encrypted_text)
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    encrypted_text = st.text_area("Enter Encrypted Data:")
    passkey = st.text_input("Enter Passkey:", type="password")

    if st.button("Decrypt"):
        if encrypted_text and passkey:
            decrypted_text = decrypt_data(encrypted_text, passkey)

            if decrypted_text:
                st.success("✅ Decryption successful!")
                st.info("**Your decrypted data:**")
                st.code(decrypted_text)
            else:
                st.error(
                    f"❌ Incorrect passkey or encrypted text! Attempts remaining: {3 - st.session_state.failed_attempts}"
                )

                if st.session_state.failed_attempts >= 3:
                    st.warning(
                        "🔒 Too many failed attempts! Redirecting to Login Page."
                    )
                    st.session_state.current_page = "Login"
                    st.rerun()
        else:
            st.error("⚠️ Both fields are required!")

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":  # Hardcoded for demo, replace with proper auth
            st.session_state.failed_attempts = 0
            st.success("✅ Reauthorized successfully! Redirecting to Retrieve Data...")
            st.session_state.current_page = "Retrieve Data"
            st.rerun()
        else:
            st.error("❌ Incorrect password!")

# Save data to a file for persistence across app restarts
if st.sidebar.button("Save Data to File"):
    with open("encrypted_data.json", "w") as f:
        json.dump(st.session_state.stored_data, f)
    st.sidebar.success("Data saved to file!")

# Load data from file
if st.sidebar.button("Load Data from File"):
    try:
        with open("encrypted_data.json", "r") as f:
            st.session_state.stored_data = json.load(f)
        st.sidebar.success("Data loaded successfully!")
    except FileNotFoundError:
        st.sidebar.error("No saved data file found!")
