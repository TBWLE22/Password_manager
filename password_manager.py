import json, hashlib, getpass, os, pyperclip, sys
from cryptography.fernet import Fernet

#Function for Hashing the Master Password.
def hash_password(password):
    sha256 = hashlib.sha256()
    sha256.update(password.encode())
    return sha256.hexdigest()

#Generate a secret key. This should be done only once.
def generate_key():
    return Fernet.generate_key()

#Initialize Fernet cipher with the provided key.
def initialize_cipher(key):
    return Fernet(key)

#Function to encrypt a password.
def encrypt_password(cipher, password):
    return cipher.encrypt(password.encode()).decode()

#Function to decrypt a password.
def decrypt_password(cipher, encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

#Function to register
def register(username, master_password):
    #Encrypt the master password before storing it
    hashed_master_password = hash_password(master_password)
    user_data = {'username': username, 'master_password': hashed_master_password}
    file_name = 'user_data.json'
    if os.path.exists(file_name) and os.path.getsize(file_name) == 0:
        with open(file_name, 'w') as file:
            json.dump(user_data, file)
            print("\n[+] Registration Complete!!\n")
    else:
        with open(file_name, 'x') as file:
            json.dump(user_data, file)
            print("\n[+] Registration Complete!!\n")

#Function for logging in
def login(username, entered_password):
    try:
        with open('user_data.json','r') as file:
            user_data = json.load(file)
        stored_password_hash = user_data.get('master_password')
        entered_password_hash = hash_password(entered_password)
        if entered_password_hash == stored_password_hash and username == user_data.get('username'):
            print("\n[+] Login Successful..\n")
        else:
            print("\n[-] Invalid Login credential. Use the credentials you registered with.\n")
            sys.exit()
    except Exception:
        print("\n[-] You have not been registered. Register first.\n")
        sys.exit()

#Function to view saved websites.
def view_websites():
    try:
        with open('passwords.json', 'r') as data:
            view = json.load(data)
            print("\nWebsites saved..\n")
            for x in view:
                print(x['website'])
            print('\n')
    except FileNotFoundError:
        print("\n[-] No saved passwords to display.\n")
    
#Load or generate the encryption key.
key_filename = 'encryption_key.key'
if os.path.exists(key_filename):
    with open(key_filename, 'rb') as key_file:
        key = key_file.read()
else:
    key = generate_key()
    with open(key_filename, 'wb') as key_file:
        key_file.write(key)
        
cipher = initialize_cipher(key)

#Funtion to save passwords.
def add_password(website, password):
    #Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        #If passwords.json does not exist,initialize it with an empty list
        data = []
    else:
        #Load existing data from passwords.json
        try:
            with open('password.json', 'r') as file:
                data = json.load(file)
        except json.JSONDecodeError:
            #Handle the case where passwords.json is empty or invalid JSON.
            data = []
    #Encrypt the password
    encrypted_password = encrypt_password(cipher, password)
    #Create a dictionary to store the website and password
    password_entry = {'website': website, 'password': encrypted_password}
    data.append(password_entry)
    #Save the updated list back to passwords.json
    with open('passwords.json','w') as file:
        json.dump(data, file, indent=4)

#Function to retrieve a saved password.
def get_password(website):
    #Check if passwords.json exists
    if not os.path.exists('passwords.json'):
        return None
    #Load existing data from passwords.json
    try:
        with open('passwords.json','r') as file:
            data = json.load(file)
    except json.JSONDecodeError:
        data = []
    #Loop through all the websited and check if the requested website exists.
    for entry in data:
        if entry['website'] == website:
            #Decrypt and return password
            decrypted_password = decrypt_password(cipher, entry['password'])
            return decrypted_password
        return None

#Loop to keep the program running until it is quit
while True:
    print("1. Register")
    print("2. Login")
    print("3. Quit")
    choice = input("Choose an option:")
    if choice == '1': #The user wants to register
        file = 'user_data.json'
        if os.path.exists(file) and os.path.getsize(file) != 0:
            print("\n[-] Master user already exists!!")
            sys.exit()
        else:
            username = input("Enter username:")
            master_password = getpass.getpass("Enter mater password:")
            register(username, master_password)
    elif choice == '2': #The user wants to log in
        file = 'user_data.json'
        if os.path.exists(file):
            username = input("Enter your username:")
            master_password = getpass.getpass("Enter your masterpassword: ")
            login(username, master_password)
        else:
            print("\n[-] You have not been registered. Please register first.\n")
            sys.exit()
        #Options after a successful login
        while True:
            print("1.Add password")
            print("2.Get password")
            print("3.View saved websites")
            print("4.Quit")
            password_choice = input("Enter your choice:")
            if password_choice == '1': #User wants to add a password
                website = input("Enter website:")
                password = getpass.getpass("Enter password:")
                #Encrypt and add the password
                add_password(website, password)
                print("\n[+] Password added!\n")
            elif password_choice == '2': #User wants to retrieve a password
                website = input("Enter website:")
                decrypted_password = get_password(website)
                if website and decrypted_password:
                    #Copy password to clipboard for convenience
                    pyperclip.copy (decrypted_password)
                    print("\n[+] Password for {website}: {decrypted_password}\n[+] Password copied to clipboard.\n")
                else:
                    print ("\n[-] Password not found!")
                    print ("\n[-] Use option 3 to see the saved websites.\n")
            elif password_choice == '3': #User wants to view saved website
                view_websites()
            elif password_choice == '4': #User wants to quit the password manager
                break
    elif choice == '3': #User wants to quit the program
        break
                