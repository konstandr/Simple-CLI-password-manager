import sqlite3


class PasswordManager:
    def __init__(self):
        self.conn = sqlite3.connect(':memory:')
        self.cursor = self.conn.cursor()
        self._create_tables()
        self.current_user = None
        self.cipher_suite = None

    def _create_tables(self):
        self.cursor.execute('''CREATE TABLE users
                                   (id INTEGER PRIMARY KEY, username TEXT UNIQUE, hashed_password TEXT, salt TEXT)''')
        self.cursor.execute('''CREATE TABLE passwords
                                   (id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, encrypted_password BLOB,
                                   FOREIGN KEY(user_id) REFERENCES users(id))''')
        self.conn.commit()

    def _hash_password(self, password, salt):
        # TODO: Implement this method
        pass

    def register_user(self, username, master_password):
        # TODO: Implement this method
        pass

    def login(self, username, master_password):
        # TODO: Implement this method
        pass

    def logout(self):
        # TODO: Implement this method
        pass

    def add_entry(self, name, password):
        # TODO: Implement this method
        pass

    def get_entry(self, name):
        # TODO: Implement this method
        pass

    def delete_entry(self, name):
        # TODO: Implement this method
        pass

    def list_entries(self):
        # TODO: Implement this method
        pass

    def change_master_password(self, new_master_password):
        # TODO: Implement this method
        pass

    def delete_user(self):
        # TODO: Implement this method
        pass

    def close(self):
        self.conn.close()



def main_loop(password_manager):
    while True:
        print("Choose an option:")#
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
            password_manager.add_entry(name, password)
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
