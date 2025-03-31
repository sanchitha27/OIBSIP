import hashlib
import os

class AuthSystem:
    def __init__(self):
        self.users_file = "users.txt"
        # Create users file if it doesn't exist
        if not os.path.exists(self.users_file):
            with open(self.users_file, 'w') as f:
                pass

    def hash_password(self, password):
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()

    def register(self, username, password):
        """Register a new user"""
        # Check if username already exists
        with open(self.users_file, 'r') as f:
            for line in f:
                stored_username, _ = line.strip().split(':')
                if stored_username == username:
                    return False, "Username already exists"

        # Store new user credentials
        hashed_password = self.hash_password(password)
        with open(self.users_file, 'a') as f:
            f.write(f"{username}:{hashed_password}\n")
        return True, "Registration successful"

    def login(self, username, password):
        """Authenticate user"""
        hashed_password = self.hash_password(password)
        with open(self.users_file, 'r') as f:
            for line in f:
                stored_username, stored_password = line.strip().split(':')
                if stored_username == username and stored_password == hashed_password:
                    return True, "Login successful"
        return False, "Invalid username or password"

    def protected_page(self, username):
        """Display protected content"""
        return f"Welcome to the protected page, {username}!\nThis is secure content."

def main():
    auth = AuthSystem()
    while True:
        print("\n1. Register")
        print("2. Login")
        print("3. Exit")
        choice = input("Choose an option (1-3): ")

        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            success, message = auth.register(username, password)
            print(message)

        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            success, message = auth.login(username, password)
            print(message)
            if success:
                print(auth.protected_page(username))

        elif choice == '3':
            print("Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()