import os
import sqlite3
import hashlib
import base64
import secrets
import string
import json
from datetime import datetime
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.Protocol.KDF import PBKDF2
import ttkbootstrap as tb
import tkinter as tk
from tkinter import messagebox, simpledialog, filedialog

# Constants
DB_FILE = 'password_auth.db'
KEY_FILE = 'secret.key'
MIN_PASSWORD_LENGTH = 8
PASSWORD_EXPIRY_DAYS = 90
IDLE_TIMEOUT_SECONDS = 300
AVAILABLE_THEMES = ["cosmo", "darkly", "flatly", "superhero", "solar", "journal"]
SAFETY_TIPS_DURATION = 5000  # 5 seconds in milliseconds


# Password Hashing Functions
def hash_password(password: str) -> tuple:
    """Hash password with PBKDF2HMAC and random salt"""
    salt = secrets.token_bytes(32)
    kdf = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000  # Iteration count
    )
    return kdf.hex(), salt.hex()


def verify_password(stored_hash: str, salt_hex: str, password: str) -> bool:
    """Verify password against stored hash"""
    try:
        salt = bytes.fromhex(salt_hex)
        new_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000
        )
        return secrets.compare_digest(new_hash, bytes.fromhex(stored_hash))
    except Exception:
        return False


# Encryption Key
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, 'rb').read()
    key = get_random_bytes(32)
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key


ENCRYPTION_KEY = load_or_create_key()


def encrypt_aes(data: str) -> str:
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(nonce + tag + ciphertext).decode()


def decrypt_aes(token: str) -> str:
    try:
        data = base64.b64decode(token.encode())
        nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
        cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
        return cipher.decrypt_and_verify(ciphertext, tag).decode()
    except (ValueError, KeyError):
        return "ERROR"
    except Exception as e:
        print(f"Decryption error: {str(e)}")
        return "ERROR"


# Database Setup
def setup_database():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    created_at TEXT NOT NULL)''')
    c.execute('''CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (user_id) REFERENCES users (id))''')
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    status TEXT,
                    timestamp TEXT)''')
    conn.commit()
    conn.close()


class PasswordManagerApp(tb.Window):
    def __init__(self):
        super().__init__(themename="cosmo")
        self.title("Password Manager")
        self.geometry("700x600")
        self.user_id = None
        self.username = None
        self.generated_passwords = set()
        self.login_time = None
        self.last_activity = datetime.utcnow()
        setup_database()

        self.bind_all("<Any-KeyPress>", lambda e: self.reset_activity())
        self.bind_all("<Any-Button>", lambda e: self.reset_activity())
        self.protocol("WM_DELETE_WINDOW", self.on_close)

        self.show_safety_tips_popup()
        self.after(SAFETY_TIPS_DURATION, self.show_login_screen)
        self.after(1000, self.check_idle_timeout)

    def on_close(self):
        self.clear_clipboard()
        self.destroy()

    def clear_clipboard(self):
        self.clipboard_clear()

    def show_safety_tips_popup(self):
        popup = tk.Toplevel(self)
        popup.title("🔒 Password Safety Tips")
        popup.geometry("400x300")
        tb.Label(popup, text="🔒 Password Safety Tips", font=("Helvetica", 16, "bold")).pack(pady=10)
        tips = (
            "- Use long passwords (12+ characters).\n"
            "- Mix upper, lower, numbers, symbols.\n"
            "- Avoid using personal info.\n"
            "- Don't reuse passwords.\n"
            "- Enable 2FA when possible.\n"
            "- Keep passwords private!"
        )
        tb.Label(popup, text=tips, justify="left").pack(pady=10)
        popup.after(SAFETY_TIPS_DURATION, popup.destroy)

    def reset_activity(self):
        self.last_activity = datetime.utcnow()

    def check_idle_timeout(self):
        if self.user_id and (datetime.utcnow() - self.last_activity).total_seconds() > IDLE_TIMEOUT_SECONDS:
            messagebox.showinfo("Timeout", "Session expired due to inactivity.")
            self.logout()
        self.after(1000, self.check_idle_timeout)

    def _clear_window(self):
        for widget in self.winfo_children():
            widget.destroy()

    def show_login_screen(self):
        self._clear_window()
        tb.Label(self, text="🔒 Login", font=("Helvetica", 24, "bold")).pack(pady=20)
        tb.Label(self, text="Username:").pack()
        self.username_entry = tb.Entry(self)
        self.username_entry.pack(pady=5)
        tb.Label(self, text="Password:").pack()
        self.password_entry = tb.Entry(self, show="*")
        self.password_entry.pack(pady=5)
        tb.Button(self, text="Login", bootstyle="success", command=self.login).pack(pady=10)
        tb.Button(self, text="Register", bootstyle="info", command=self.show_register_screen).pack()

    def show_register_screen(self):
        self._clear_window()
        tb.Label(self, text="📝 Register", font=("Helvetica", 24, "bold")).pack(pady=20)
        tb.Label(self, text="Username:").pack()
        self.reg_username_entry = tb.Entry(self)
        self.reg_username_entry.pack(pady=5)

        tb.Label(self, text="Password:").pack()
        self.reg_password_entry = tb.Entry(self, show="*")
        self.reg_password_entry.pack(pady=5)

        # Password strength meter
        self.strength_bar = tb.Progressbar(self, length=200, maximum=5)
        self.strength_bar.pack(pady=5)

        # Password requirements feedback
        self.requirements_frame = tb.Frame(self)
        self.requirements_frame.pack(pady=5)

        self.requirement_labels = {
            'length': tb.Label(self.requirements_frame, text=f"✓ At least {MIN_PASSWORD_LENGTH} characters",
                               foreground="gray"),
            'lower': tb.Label(self.requirements_frame, text="✓ Lowercase letter", foreground="gray"),
            'upper': tb.Label(self.requirements_frame, text="✓ Uppercase letter", foreground="gray"),
            'digit': tb.Label(self.requirements_frame, text="✓ Digit", foreground="gray"),
            'special': tb.Label(self.requirements_frame, text="✓ Special character", foreground="gray")
        }

        for label in self.requirement_labels.values():
            label.pack(anchor="w")

        self.reg_password_entry.bind("<KeyRelease>", self.update_password_feedback)

        tb.Label(self, text="Confirm Password:").pack()
        self.reg_confirm_password_entry = tb.Entry(self, show="*")
        self.reg_confirm_password_entry.pack(pady=5)

        tb.Button(self, text="Confirm Registration", bootstyle="success", command=self.register_user).pack(pady=10)
        tb.Button(self, text="Back to Login", bootstyle="secondary", command=self.show_login_screen).pack()

    def update_password_feedback(self, event=None):
        password = self.reg_password_entry.get()
        strength = self.password_strength(password)
        self.strength_bar['value'] = strength

        # Update strength bar color
        if strength <= 2:
            self.strength_bar.configure(bootstyle="danger")
        elif strength == 3:
            self.strength_bar.configure(bootstyle="warning")
        else:
            self.strength_bar.configure(bootstyle="success")

        # Update requirement labels
        requirements = self.check_password_requirements(password)

        for req, label in self.requirement_labels.items():
            if req in requirements:
                label.config(foreground="red", text=f"✗ {label.cget('text')[1:]}")
            else:
                label.config(foreground="green", text=f"✓ {label.cget('text')[1:]}")

    def password_strength(self, password: str) -> int:
        score = 0
        if len(password) >= MIN_PASSWORD_LENGTH:
            score += 1
        if any(c.islower() for c in password):
            score += 1
        if any(c.isupper() for c in password):
            score += 1
        if any(c.isdigit() for c in password):
            score += 1
        if any(c in string.punctuation for c in password):
            score += 1
        return score

    def check_password_requirements(self, password):
        """Check password and return list of missing requirements."""
        missing = []
        if len(password) < MIN_PASSWORD_LENGTH:
            missing.append('length')
        if not any(c.islower() for c in password):
            missing.append('lower')
        if not any(c.isupper() for c in password):
            missing.append('upper')
        if not any(c.isdigit() for c in password):
            missing.append('digit')
        if not any(c in string.punctuation for c in password):
            missing.append('special')
        return missing

    def register_user(self):
        username = self.reg_username_entry.get()
        password = self.reg_password_entry.get()
        confirm_password = self.reg_confirm_password_entry.get()

        if not username or not password or not confirm_password:
            messagebox.showerror("Error", "All fields are required.")
            return

        if password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match.")
            return

        missing_requirements = self.check_password_requirements(password)
        if missing_requirements:
            messagebox.showerror("Weak Password",
                                 "Password doesn't meet requirements. Please check the feedback.")
            return

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            pwd_hash, salt_hex = hash_password(password)
            c.execute("INSERT INTO users (username, password_hash, salt, created_at) VALUES (?, ?, ?, ?)",
                      (username, pwd_hash, salt_hex, datetime.utcnow().isoformat()))
            conn.commit()
            messagebox.showinfo("Success", "Registered successfully! Please log in.")
            self.show_login_screen()
        except sqlite3.IntegrityError:
            messagebox.showerror("Error", "Username already exists.")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error: {str(e)}")
        finally:
            conn.close()

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("SELECT id, password_hash, salt FROM users WHERE username = ?", (username,))
            result = c.fetchone()
            if result:
                user_id, stored_hash, salt_hex = result
                if verify_password(stored_hash, salt_hex, password):
                    self.user_id = user_id
                    self.username = username
                    self.login_time = datetime.utcnow()
                    self.log_attempt(username, "success")
                    self.show_main_menu()
                else:
                    self.log_attempt(username, "fail")
                    messagebox.showerror("Login Failed", "Incorrect password.")
            else:
                self.log_attempt(username, "fail")
                messagebox.showerror("Login Failed", "Username not found.")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error: {str(e)}")
        finally:
            conn.close()

    def log_attempt(self, username, status):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO logs (username, status, timestamp) VALUES (?, ?, ?)",
                      (username, status, datetime.utcnow().isoformat()))
            conn.commit()
        except sqlite3.Error as e:
            print(f"Logging error: {str(e)}")
        finally:
            conn.close()

    def logout(self):
        self.clear_clipboard()
        self.user_id = None
        self.username = None
        self.show_login_screen()

    def show_main_menu(self):
        self._clear_window()
        tb.Label(self, text=f"👋 Welcome, {self.username}!", font=("Helvetica", 20, "bold")).pack(pady=20)
        vault = tb.LabelFrame(self, text="🔑 Password Vault", padding=10)
        vault.pack(padx=20, pady=10, fill="both")
        tb.Button(vault, text="View Entries", bootstyle="primary", command=self.show_view_entries, width=30).pack(
            pady=5)
        tb.Button(vault, text="Add Entry", bootstyle="primary", command=self.add_entry, width=30).pack(pady=5)

        tools = tb.LabelFrame(self, text="🛠️ Tools", padding=10)
        tools.pack(padx=20, pady=10, fill="both")
        tb.Button(tools, text="Generate Password", bootstyle="warning", command=self.generate_password, width=30).pack(
            pady=5)
        tb.Button(tools, text="Password Safety Tips", bootstyle="info", command=self.show_safety_tips_popup_manual,
                  width=30).pack(pady=5)

        account = tb.LabelFrame(self, text="👤 Account", padding=10)
        account.pack(padx=20, pady=10, fill="both")
        tb.Button(account, text="Logout", bootstyle="danger", command=self.logout, width=30).pack(pady=5)
        tb.Label(account, text="Theme:").pack(pady=5)
        self.theme_var = tk.StringVar(value=self.style.theme.name)
        tb.OptionMenu(account, self.theme_var, *AVAILABLE_THEMES, command=self.change_theme).pack()

        if self.login_time:
            tb.Label(self, text=f"Logged in at {self.login_time.strftime('%Y-%m-%d %H:%M:%S')}",
                     font=("Helvetica", 8)).pack(side="bottom", pady=5)

    def show_safety_tips_popup_manual(self):
        self.show_safety_tips_popup()

    def change_theme(self, new_theme):
        self.style.theme_use(new_theme)

    def add_entry(self):
        # Create the add entry dialog as a Toplevel window
        add_window = tb.Toplevel(self)
        add_window.title("Add Password Entry")
        add_window.geometry("500x500")

        # Title field
        tb.Label(add_window, text="Title:").pack(pady=5)
        title_entry = tb.Entry(add_window)
        title_entry.pack(pady=5, fill="x", padx=20)

        # Username field
        tb.Label(add_window, text="Username:").pack(pady=5)
        username_entry = tb.Entry(add_window)
        username_entry.pack(pady=5, fill="x", padx=20)

        # Password field with strength meter
        tb.Label(add_window, text="Password:").pack(pady=5)
        password_entry = tb.Entry(add_window, show="*")
        password_entry.pack(pady=5, fill="x", padx=20)

        # Password strength meter
        tb.Label(add_window, text="Password Strength:").pack(pady=5)
        strength_bar = tb.Progressbar(add_window, length=200, maximum=5)
        strength_bar.pack(pady=5)

        # Password requirements feedback
        requirements_frame = tb.Frame(add_window)
        requirements_frame.pack(pady=5)

        requirement_labels = {
            'length': tb.Label(requirements_frame, text=f"✓ At least {MIN_PASSWORD_LENGTH} characters",
                               foreground="gray"),
            'lower': tb.Label(requirements_frame, text="✓ Lowercase letter", foreground="gray"),
            'upper': tb.Label(requirements_frame, text="✓ Uppercase letter", foreground="gray"),
            'digit': tb.Label(requirements_frame, text="✓ Digit", foreground="gray"),
            'special': tb.Label(requirements_frame, text="✓ Special character", foreground="gray")
        }

        for label in requirement_labels.values():
            label.pack(anchor="w")

        # Bind key release to update feedback
        password_entry.bind("<KeyRelease>", lambda e: self.update_entry_password_feedback(
            password_entry.get(), strength_bar, requirement_labels))

        # Button frame for Generate and Create
        button_frame = tb.Frame(add_window)
        button_frame.pack(pady=10)

        # Generate button - generates a new password
        tb.Button(button_frame, text="Generate", bootstyle="warning",
                  command=lambda: self.fill_generated_password(password_entry, strength_bar, requirement_labels)).pack(
            side="left", padx=5)

        # Create button - saves the manually entered password
        tb.Button(button_frame, text="Create", bootstyle="success",
                  command=lambda: self.save_new_entry(
                      title_entry.get(),
                      username_entry.get(),
                      password_entry.get(),
                      add_window,
                      strength_bar,
                      requirement_labels
                  )).pack(side="right", padx=5)

    def update_entry_password_feedback(self, password, strength_bar, requirement_labels):
        strength = self.password_strength(password)
        strength_bar['value'] = strength

        # Update strength bar color
        if strength <= 2:
            strength_bar.configure(bootstyle="danger")
        elif strength == 3:
            strength_bar.configure(bootstyle="warning")
        else:
            strength_bar.configure(bootstyle="success")

        # Update requirement labels
        requirements = self.check_password_requirements(password)

        for req, label in requirement_labels.items():
            if req in requirements:
                label.config(foreground="red", text=f"✗ {label.cget('text')[1:]}")
            else:
                label.config(foreground="green", text=f"✓ {label.cget('text')[1:]}")

    def fill_generated_password(self, password_entry, strength_bar, requirement_labels):
        """Generate a password that definitely meets all requirements"""
        length = simpledialog.askinteger("Password Length",
                                         "Enter password length:",
                                         minvalue=MIN_PASSWORD_LENGTH,
                                         initialvalue=16)
        if not length:
            return

        # Ensure we always include at least one of each required character type
        lowercase = secrets.choice(string.ascii_lowercase)
        uppercase = secrets.choice(string.ascii_uppercase)
        digit = secrets.choice(string.digits)
        special = secrets.choice(string.punctuation)

        # Generate the remaining characters
        remaining_length = length - 4
        if remaining_length > 0:
            alphabet = string.ascii_letters + string.digits + string.punctuation
            remaining = ''.join(secrets.choice(alphabet) for _ in range(remaining_length))
        else:
            remaining = ''

        # Combine and shuffle
        combined = list(lowercase + uppercase + digit + special + remaining)
        secrets.SystemRandom().shuffle(combined)
        pwd = ''.join(combined)

        password_entry.delete(0, tk.END)
        password_entry.insert(0, pwd)
        self.update_entry_password_feedback(pwd, strength_bar, requirement_labels)

    def save_new_entry(self, title, username, password, window, strength_bar, requirement_labels):
        if not title or not username or not password:
            messagebox.showerror("Error", "All fields are required.")
            return

        missing_requirements = self.check_password_requirements(password)
        if missing_requirements:
            messagebox.showerror("Weak Password",
                                 "Password doesn't meet requirements. Please check the feedback.")
            return

        encrypted_pwd = encrypt_aes(password)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("INSERT INTO entries (user_id, title, username, password, created_at) VALUES (?, ?, ?, ?, ?)",
                      (self.user_id, title, username, encrypted_pwd, datetime.utcnow().isoformat()))
            conn.commit()
            messagebox.showinfo("Success", "Entry added successfully!")
            window.destroy()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error: {str(e)}")
        finally:
            conn.close()

    def generate_password(self, silent=False):
        """Standalone password generator that always meets requirements"""
        length = simpledialog.askinteger("Password Length",
                                         "Enter password length:",
                                         minvalue=MIN_PASSWORD_LENGTH,
                                         initialvalue=16)
        if not length:
            return None

        # Ensure we always include at least one of each required character type
        lowercase = secrets.choice(string.ascii_lowercase)
        uppercase = secrets.choice(string.ascii_uppercase)
        digit = secrets.choice(string.digits)
        special = secrets.choice(string.punctuation)

        # Generate the remaining characters
        remaining_length = length - 4
        if remaining_length > 0:
            alphabet = string.ascii_letters + string.digits + string.punctuation
            remaining = ''.join(secrets.choice(alphabet) for _ in range(remaining_length))
        else:
            remaining = ''

        # Combine and shuffle
        combined = list(lowercase + uppercase + digit + special + remaining)
        secrets.SystemRandom().shuffle(combined)
        pwd = ''.join(combined)

        self.clipboard_clear()
        self.clipboard_append(pwd)
        if not silent:
            messagebox.showinfo("Generated",
                                f"Password copied to clipboard (will clear in 30s):\n{pwd}")
        self.after(30000, self.clear_clipboard)
        return pwd

    def copy_password(self, entry_id):
        """Copy password to clipboard with auto-clear"""
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("SELECT password FROM entries WHERE id = ?", (entry_id,))
            result = c.fetchone()
            if result:
                encrypted_pwd = result[0]
                decrypted_pwd = decrypt_aes(encrypted_pwd)
                if decrypted_pwd != "ERROR":
                    self.clipboard_clear()
                    self.clipboard_append(decrypted_pwd)
                    # Show feedback in the treeview
                    self.tree.set(entry_id, "Password", "Copied!")
                    self.after(2000, lambda: self.refresh_tree())  # Reset after 2 seconds
                    # Auto-clear clipboard after 30 seconds
                    self.after(30000, self.clear_clipboard)
                    return
            messagebox.showerror("Error", "Could not copy password")
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error: {str(e)}")
        finally:
            conn.close()

    def show_view_entries(self):
        view = tb.Toplevel(self)
        view.title("Your Entries")
        view.geometry("700x550")

        top_frame = tb.Frame(view)
        top_frame.pack(fill="x", pady=5)

        tb.Label(top_frame, text="Search:").pack(side="left")
        self.search_var = tk.StringVar()
        search_entry = tb.Entry(top_frame, textvariable=self.search_var)
        search_entry.pack(side="left", expand=True, fill="x", padx=5)
        search_entry.bind("<KeyRelease>", self.filter_entries)

        self.show_password_var = tk.BooleanVar(value=False)
        show_pwd_checkbox = tb.Checkbutton(top_frame, text="Show Passwords", variable=self.show_password_var,
                                           command=self.refresh_tree)
        show_pwd_checkbox.pack(side="right", padx=5)

        columns = ("Title", "Username", "Password")
        self.tree = tb.Treeview(view, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=200)
        self.tree.tag_configure('safe', background='#d4edda')
        self.tree.tag_configure('warning', background='#fff3cd')
        self.tree.tag_configure('expired', background='#f8d7da')
        self.tree.pack(expand=True, fill='both')

        self.tree.bind("<Button-3>", self.show_entry_menu)  # Right-click

        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("SELECT id, title, username, password, created_at FROM entries WHERE user_id = ?",
                      (self.user_id,))
            self.entries = c.fetchall()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error: {str(e)}")
            view.destroy()
            return
        finally:
            conn.close()

        self.refresh_tree()

    def refresh_tree(self):
        search = self.search_var.get().lower()
        self.tree.delete(*self.tree.get_children())

        for entry_id, title, username, pwd_enc, created_at in self.entries:
            # Decrypt password
            decrypted_pwd = decrypt_aes(pwd_enc)
            entry_date = datetime.fromisoformat(created_at)
            age_days = (datetime.utcnow() - entry_date).days

            # Determine tag based on password age
            if age_days > PASSWORD_EXPIRY_DAYS:
                tag = 'expired'
            elif age_days > (PASSWORD_EXPIRY_DAYS - 10):
                tag = 'warning'
            else:
                tag = 'safe'

            # Determine password display
            if (self.tree.exists(entry_id) and
                    self.tree.set(entry_id, "Password") == "Copied!"):
                password_display = "Copied!"
            elif self.show_password_var.get():
                password_display = decrypted_pwd
            else:
                password_display = (
                    decrypted_pwd[:3] + '*' * (len(decrypted_pwd) - 3)
                    if decrypted_pwd != "ERROR" else "ERROR"
                )

            # Only show entries that match search
            if search in title.lower() or search in username.lower():
                self.tree.insert(
                    '',
                    'end',
                    iid=entry_id,
                    values=(title, username, password_display),
                    tags=(tag,)
                )

    def filter_entries(self, event=None):
        self.refresh_tree()

    def show_entry_menu(self, event):
        try:
            selected_item = self.tree.identify_row(event.y)
            if not selected_item:
                return
            self.tree.selection_set(selected_item)

            menu = tk.Menu(self, tearoff=0)
            menu.add_command(label="Copy Password", command=lambda: self.copy_password(selected_item))
            menu.add_command(label="Edit Entry", command=lambda: self.edit_entry(selected_item))
            menu.add_command(label="Delete Entry", command=lambda: self.delete_entry(selected_item))
            menu.post(event.x_root, event.y_root)
        except Exception as e:
            print(e)

    def edit_entry(self, entry_id):
        # Create edit window
        edit_window = tb.Toplevel(self)
        edit_window.title("Edit Entry")
        edit_window.geometry("500x500")

        # Get current entry data
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("SELECT title, username, password FROM entries WHERE id = ?", (entry_id,))
            title, username, pwd_enc = c.fetchone()
            current_password = decrypt_aes(pwd_enc)
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error: {str(e)}")
            edit_window.destroy()
            return
        finally:
            conn.close()

        # Title field
        tb.Label(edit_window, text="Title:").pack(pady=5)
        title_entry = tb.Entry(edit_window)
        title_entry.insert(0, title)
        title_entry.pack(pady=5, fill="x", padx=20)

        # Username field
        tb.Label(edit_window, text="Username:").pack(pady=5)
        username_entry = tb.Entry(edit_window)
        username_entry.insert(0, username)
        username_entry.pack(pady=5, fill="x", padx=20)

        # Password field with strength meter
        tb.Label(edit_window, text="Password:").pack(pady=5)
        password_entry = tb.Entry(edit_window, show="*")
        password_entry.insert(0, current_password)
        password_entry.pack(pady=5, fill="x", padx=20)

        # Password strength meter
        tb.Label(edit_window, text="Password Strength:").pack(pady=5)
        strength_bar = tb.Progressbar(edit_window, length=200, maximum=5)
        strength_bar.pack(pady=5)

        # Password requirements feedback
        requirements_frame = tb.Frame(edit_window)
        requirements_frame.pack(pady=5)

        requirement_labels = {
            'length': tb.Label(requirements_frame, text=f"✓ At least {MIN_PASSWORD_LENGTH} characters",
                               foreground="gray"),
            'lower': tb.Label(requirements_frame, text="✓ Lowercase letter", foreground="gray"),
            'upper': tb.Label(requirements_frame, text="✓ Uppercase letter", foreground="gray"),
            'digit': tb.Label(requirements_frame, text="✓ Digit", foreground="gray"),
            'special': tb.Label(requirements_frame, text="✓ Special character", foreground="gray")
        }

        for label in requirement_labels.values():
            label.pack(anchor="w")

        # Initialize with current password feedback
        self.update_entry_password_feedback(current_password, strength_bar, requirement_labels)

        # Bind key release to update feedback
        password_entry.bind("<KeyRelease>", lambda e: self.update_entry_password_feedback(
            password_entry.get(), strength_bar, requirement_labels))

        # Button frame for Generate and Save
        button_frame = tb.Frame(edit_window)
        button_frame.pack(pady=10)

        # Generate button - generates a new password
        tb.Button(button_frame, text="Generate", bootstyle="warning",
                  command=lambda: self.fill_generated_password(password_entry, strength_bar, requirement_labels)).pack(
            side="left", padx=5)

        # Save button - saves the changes
        tb.Button(button_frame, text="Save", bootstyle="success",
                  command=lambda: self.save_edited_entry(
                      entry_id,
                      title_entry.get(),
                      username_entry.get(),
                      password_entry.get(),
                      edit_window,
                      strength_bar,
                      requirement_labels
                  )).pack(side="right", padx=5)

    def save_edited_entry(self, entry_id, new_title, new_username, new_password, window, strength_bar,
                          requirement_labels):
        if not new_title or not new_username or not new_password:
            messagebox.showerror("Error", "All fields are required.")
            return

        missing_requirements = self.check_password_requirements(new_password)
        if missing_requirements:
            messagebox.showerror("Weak Password",
                                 "Password doesn't meet requirements. Please check the feedback.")
            return

        encrypted_pwd = encrypt_aes(new_password)
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        try:
            c.execute("UPDATE entries SET title = ?, username = ?, password = ? WHERE id = ?",
                      (new_title, new_username, encrypted_pwd, entry_id))
            conn.commit()
            messagebox.showinfo("Updated", "Password entry updated successfully!")
            window.destroy()
            self.refresh_tree()
        except sqlite3.Error as e:
            messagebox.showerror("Database Error", f"Error: {str(e)}")
        finally:
            conn.close()

    def delete_entry(self, entry_id):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            try:
                c.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
                conn.commit()
                messagebox.showinfo("Deleted", "Password entry deleted successfully!")
                self.refresh_tree()
            except sqlite3.Error as e:
                messagebox.showerror("Database Error", f"Error: {str(e)}")
            finally:
                conn.close()


if __name__ == "__main__":
    app = PasswordManagerApp()
    app.mainloop()