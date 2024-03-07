import hashlib
import os
import sqlite3
import bcrypt
from cryptography.fernet import Fernet


class PasswordManager:
    def __init__(self, db_file='pass'):
        self.db_file = db_file  # Store the filename
        if not os.path.isfile(self.db_file):  # Check if file exists
            self.conn = sqlite3.connect(self.db_file)
            self.cursor = self.conn.cursor()
            self.create_tables()
        else:
            self.conn = sqlite3.connect(self.db_file)
            self.cursor = self.conn.cursor()
        self.current_user = None
        self.cipher_suite = None
        self.user_id = None

    def create_tables(self):
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS users
                                   (id INTEGER PRIMARY KEY, username TEXT UNIQUE, hashed_password TEXT)''')
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS passwords
                                   (id INTEGER PRIMARY KEY, user_id INTEGER, service_name TEXT, username TEXT, encrypted_password BLOB,
                                   FOREIGN KEY(user_id) REFERENCES users(id))''')

        self.conn.commit()

    def hash_password(self, password):
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode(), salt)
        return hashed_password.decode()  # Store as string

    def register_user(self, username, master_password):
        hashed_password = self.hash_password(master_password)
        try:
            self.cursor.execute("INSERT INTO users (username, hashed_password) VALUES (?, ?)",
                                (username, hashed_password))
            self.conn.commit()
        except sqlite3.IntegrityError:
            print("Username already exists.")

    def login(self, username, master_password):
        self.cursor.execute("SELECT id, hashed_password FROM users WHERE username = ?", (username,))
        user = self.cursor.fetchone()
        if user:
            self.user_id, hashed_password = user

            if bcrypt.checkpw(master_password.encode(), hashed_password.encode()):
                self.current_user = self.user_id
                print("Login successful")
                return True
            else:
                print("Incorrect password")
        else:
            print("Username not found")

    def logout(self):
        self.current_user = None
        self.cipher_suite = None
        print("Logged out")

    def add_entry(self, service_name, username, password):
        if not self.current_user:
            print("User not connected. Please log in.")
            return

        master_password = password

        # Επιβεβαιώστε τον master κωδικό
        self.cursor.execute("SELECT hashed_password FROM users WHERE id = ?", (self.current_user,))
        hashed_master_password = self.cursor.fetchone()[0]

        if bcrypt.checkpw(master_password.encode(), hashed_master_password.encode()):
            print("Master password correct.")
            # Κρυπτογράφηση του password
            cipher_suite = Fernet(self.get_user_key(master_password.encode()))
            encrypted_password = cipher_suite.encrypt(password.encode())

            # Προσθήκη του entry στον πίνακα passwords
            self.cursor.execute("INSERT INTO passwords (user_id, service_name, username, encrypted_password) VALUES (?, ?, ?, ?)",
                                (self.current_user, service_name, username, encrypted_password))
            self.connection.commit()
            print("Entry added successfully.")
        else:
            print("Incorrect master password.")


    def get_entry(self, name):
        if self.current_user:
            pass

    def delete_entry(self, name):
        if self.current_user:
            self.cursor.execute("DELETE FROM passwords WHERE user_id = ? AND name = ?", (self.current_user, name))
            self.conn.commit()
        pass

    def list_entries(self):
        if self.current_user:
            self.cursor.execute("SELECT name FROM passwords WHERE user_id = ?", (self.current_user,))
            entries = self.cursor.fetchall()
            for entry in entries:
                print(entry[0])
        else:
            print("Not logged in")
        pass

    def change_master_password(self, new_master_password):
        if self.current_user:
            hashed_password = self.hash_password(new_master_password)
            self.cursor.execute("UPDATE users SET hashed_password = ? WHERE id = ?",
                                (hashed_password, self.current_user))
            self.conn.commit()
        pass

    def delete_user(self):
        if self.current_user:
            self.cursor.execute("DELETE FROM passwords WHERE user_id = ?", (self.current_user,))
            self.cursor.execute("DELETE FROM users WHERE id = ?", (self.current_user,))
            self.conn.commit()
            self.current_user = None
        pass

    def close(self):
        self.conn.close()

    def get_user_key(self, master_password):
        return master_password


def main_loop(password_manager):
    while True:
        print("Choose an option:")  #
        print("1. Register user")
        print("2. Login")
        print("3. Logout")
        print("4. Add entry")
        print("5. Get entries")
        print("6. Delete entries")
        print("7. List entries")
        print("8. Change master password")
        print("9. Delete user")
        print("10. Quit")
        command = input("Enter command: ")
        if command == "1":
            username = input("Username: ")
            master_password = input("Master password: ")
            password_manager.register_user(username, master_password)
        elif command == "2":
            username = input("Username: ")
            master_password = input("Master password: ")
            password_manager.login(username, master_password)
        elif command == "3":
            password_manager.logout()
        elif command == "4":
            name = input("Name: ")
            password = input("Password: ")
            service_name = input("Service name: ")
            password_manager.add_entry(service_name, name, password)
        elif command == "5":
            name = input("Name: ")
            print("Password:", password_manager.get_entry(name))
        elif command == "6":
            name = input("Name: ")
            password_manager.delete_entry(name)
        elif command == "7":
            password_manager.list_entries()
        elif command == "8":
            new_master_password = input("New master password: ")
            password_manager.change_master_password(new_master_password)
        elif command == "9":
            password_manager.delete_user()
        elif command == "10":
            password_manager.close()
            break


if __name__ == "__main__":
    password_manager = PasswordManager()
    main_loop(password_manager)
