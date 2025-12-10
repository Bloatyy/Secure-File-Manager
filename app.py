"""
Secure File Manager - Modern Application with Full UI
Features: User Management, File Permissions, Encryption, Search, Logs Export
"""

import os
import json
import hashlib
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Dict, List

import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

# Feature flags
USE_CUSTOM = False
USE_CRYPTO = False
USE_PDF = False

try:
    import customtkinter as ctk
    USE_CUSTOM = True
except ImportError:
    pass

try:
    from cryptography.fernet import Fernet
    USE_CRYPTO = True
except ImportError:
    pass

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas
    USE_PDF = True
except ImportError:
    pass

# ==================== CONFIGURATION ====================
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
SECURE_DIR = DATA_DIR / "secure_files"
USERS_FILE = DATA_DIR / "users.json"
PERMS_FILE = DATA_DIR / "permissions.json"
LOG_FILE = DATA_DIR / "logs.txt"
KEY_FILE = DATA_DIR / "key.key"

# Create directories
for directory in (DATA_DIR, SECURE_DIR):
    directory.mkdir(parents=True, exist_ok=True)

# ==================== THEME ====================
class Theme:
    PRIMARY = "#2E86AB"
    SECONDARY = "#AD2970"
    SUCCESS = "#28A745"
    DANGER = "#DC3545"
    LIGHT = "#F8F9FA"
    DARK = "#343A40"
    WHITE = "#FFFFFF"
    BACKGROUND = "#F5F7FA"
    
    FONT_FAMILY = "Segoe UI"
    HEADER_SIZE = 24
    TITLE_SIZE = 18
    SUBTITLE_SIZE = 14
    BODY_SIZE = 12
    SMALL_SIZE = 10
    
    BTN_WIDTH = 300
    BTN_HEIGHT = 40  

# ==================== UI UTILITIES ====================
def show_message(title: str, message: str, type: str = "info"):
    """Display message box"""
    if type == "error":
        messagebox.showerror(title, message)
    elif type == "warning":
        messagebox.showwarning(title, message)
    else:
        messagebox.showinfo(title, message)

def ask_confirmation(title: str, message: str) -> bool:
    """Ask for yes/no confirmation"""
    return messagebox.askyesno(title, message)

def ask_string(title: str, prompt: str, default: str = "") -> Optional[str]:
    """Ask for string input"""
    return simpledialog.askstring(title, prompt, initialvalue=default)

# ==================== SERVICES ====================

class AuthService:
    """Authentication and user management"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password using SHA256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    @staticmethod
    def load_users() -> Dict:
        """Load users from JSON"""
        try:
            if USERS_FILE.exists():
                return json.loads(USERS_FILE.read_text())
        except Exception:
            pass
        return {}
    
    @staticmethod
    def save_users(users: Dict):
        """Save users to JSON"""
        USERS_FILE.write_text(json.dumps(users, indent=4))
    
    @staticmethod
    def initialize_admin():
        """Create default admin if no users exist"""
        if not USERS_FILE.exists() or not USERS_FILE.read_text().strip():
            admin_user = {
                "admin": {
                    "password": AuthService.hash_password("admin123"),
                    "role": "admin"
                }
            }
            AuthService.save_users(admin_user)
    
    def authenticate(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Verify credentials, return (success, role)"""
        users = self.load_users()
        if username in users:
            if users[username]["password"] == self.hash_password(password):
                return True, users[username].get("role", "user")
        return False, None
    
    def create_user(self, username: str, password: str, role: str = "user") -> Tuple[bool, str]:
        """Create new user"""
        users = self.load_users()
        if username in users:
            return False, "User already exists"
        users[username] = {"password": self.hash_password(password), "role": role}
        self.save_users(users)
        return True, "User created"
    
    def delete_user(self, username: str) -> bool:
        """Delete user (not admin)"""
        if username == "admin":
            return False
        users = self.load_users()
        if username in users:
            del users[username]
            self.save_users(users)
            return True
        return False

class PermissionService:
    """File permission management"""
    
    @staticmethod
    def load_perms() -> Dict:
        """Load permissions"""
        try:
            if PERMS_FILE.exists():
                return json.loads(PERMS_FILE.read_text())
        except Exception:
            pass
        return {}
    
    @staticmethod
    def save_perms(perms: Dict):
        """Save permissions"""
        PERMS_FILE.write_text(json.dumps(perms, indent=4))
    
    @staticmethod
    def check_perm(username: str, filename: str, action: str) -> bool:
        """Check if user has permission"""
        if username == "admin":
            return True
        perms = PermissionService.load_perms()
        return action in perms.get(username, {}).get(filename, [])
    
    @staticmethod
    def set_perm(username: str, filename: str, read: bool = False, write: bool = False, delete: bool = False):
        """Set permissions"""
        perms = PermissionService.load_perms()
        if username not in perms:
            perms[username] = {}
        perms[username][filename] = []
        if read:
            perms[username][filename].append("read")
        if write:
            perms[username][filename].append("write")
        if delete:
            perms[username][filename].append("delete")
        PermissionService.save_perms(perms)

class EncryptionService:
    """File encryption/decryption"""
    
    def __init__(self):
        self.fernet = None
        if USE_CRYPTO:
            if KEY_FILE.exists():
                key = KEY_FILE.read_bytes()
            else:
                key = Fernet.generate_key()
                KEY_FILE.write_bytes(key)
            self.fernet = Fernet(key)
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data"""
        if USE_CRYPTO and self.fernet:
            return self.fernet.encrypt(data)
        # XOR fallback
        key = 0x9F
        return bytes([b ^ key for b in data])
    
    def decrypt(self, token: bytes) -> bytes:
        """Decrypt data"""
        if USE_CRYPTO and self.fernet:
            return self.fernet.decrypt(token)
        # XOR fallback
        key = 0x9F
        return bytes([b ^ key for b in token])
    
    def encrypt_text(self, text: str) -> bytes:
        """Encrypt text"""
        return self.encrypt(text.encode("utf-8"))
    
    def decrypt_text(self, token: bytes) -> str:
        """Decrypt text"""
        return self.decrypt(token).decode("utf-8", errors="ignore")

class FileService:
    """Secure file operations"""
    
    def __init__(self):
        self.encryption = EncryptionService()
    
    def list_files(self, search: str = "") -> List[str]:
        """List files matching search"""
        files = []
        for f in SECURE_DIR.iterdir():
            if f.is_file() and f.suffix == ".enc":
                name = f.stem
                if search.lower() in name.lower():
                    files.append(name)
        return sorted(files)
    
    def save_file(self, filename: str, content: str, username: str) -> bool:
        """Save encrypted file"""
        try:
            encrypted = self.encryption.encrypt_text(content)
            path = SECURE_DIR / f"{filename}.enc"
            path.write_bytes(encrypted)
            PermissionService.set_perm(username, filename, read=True, write=True, delete=True)
            log_activity(username, "create", filename, "SUCCESS")
            return True
        except Exception as e:
            log_activity(username, "create", filename, f"FAILED: {e}")
            return False
    
    def read_file(self, filename: str, username: str) -> Optional[str]:
        """Read encrypted file"""
        path = SECURE_DIR / f"{filename}.enc"
        if not path.exists():
            log_activity(username, "read", filename, "FAILED: Not found")
            return None
        try:
            encrypted = path.read_bytes()
            content = self.encryption.decrypt_text(encrypted)
            log_activity(username, "read", filename, "SUCCESS")
            return content
        except Exception as e:
            log_activity(username, "read", filename, f"FAILED: {e}")
            return None
    
    def delete_file(self, filename: str, username: str) -> bool:
        """Delete encrypted file"""
        path = SECURE_DIR / f"{filename}.enc"
        if path.exists():
            path.unlink()
            log_activity(username, "delete", filename, "SUCCESS")
            return True
        log_activity(username, "delete", filename, "FAILED: Not found")
        return False

class LogService:
    """Activity logging"""
    
    @staticmethod
    def get_recent(limit: int = 50) -> str:
        """Get recent logs"""
        try:
            with open(LOG_FILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
                return "".join(lines[-limit:])
        except Exception:
            return "No logs available"
    
    @staticmethod
    def export_txt() -> Tuple[bool, str]:
        """Export logs to TXT"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = DATA_DIR / f"logs_{timestamp}.txt"
            dest.write_text(LOG_FILE.read_text())
            return True, f"Logs exported to {dest}"
        except Exception as e:
            return False, f"Export failed: {e}"
    
    @staticmethod
    def export_pdf() -> Tuple[bool, str]:
        """Export logs to PDF"""
        if not USE_PDF:
            return False, "PDF export requires reportlab"
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = DATA_DIR / f"logs_{timestamp}.pdf"
            
            text = LOG_FILE.read_text()
            c = canvas.Canvas(str(dest), pagesize=letter)
            width, height = letter
            
            c.setFont("Helvetica", 12)
            c.drawString(40, height - 40, "Secure File Manager - Activity Log")
            c.setFont("Helvetica", 10)
            
            y = height - 80
            for line in text.splitlines()[:100]:
                if y < 40:
                    c.showPage()
                    y = height - 40
                c.drawString(40, y, line[:180])
                y -= 15
            
            c.save()
            return True, f"Logs exported to {dest}"
        except Exception as e:
            return False, f"Export failed: {e}"

def log_activity(username: str, action: str, filename: str, status: str):
    """Log activity"""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = f"[{timestamp}] {username} {action.upper()} {filename} ({status})\n"
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(entry)

# ==================== UI COMPONENTS ====================

class ModernButton(tk.Button if not USE_CUSTOM else ctk.CTkButton):
    """Styled button"""
    def __init__(self, master, **kwargs):
        if not USE_CUSTOM:
            kwargs.setdefault("font", (Theme.FONT_FAMILY, Theme.BODY_SIZE))
            kwargs.setdefault("bg", Theme.PRIMARY)
            kwargs.setdefault("fg", Theme.WHITE)
            kwargs.setdefault("padx", 20)
            kwargs.setdefault("pady", 10)
            kwargs.setdefault("cursor", "hand2")
        super().__init__(master, **kwargs)

class ModernEntry(tk.Entry if not USE_CUSTOM else ctk.CTkEntry):
    """Styled entry"""
    def __init__(self, master, **kwargs):
        if not USE_CUSTOM:
            kwargs.setdefault("font", (Theme.FONT_FAMILY, Theme.BODY_SIZE))
            kwargs.setdefault("width", 30)
        super().__init__(master, **kwargs)

class ModernLabel(tk.Label if not USE_CUSTOM else ctk.CTkLabel):
    """Styled label"""
    def __init__(self, master, **kwargs):
        # Allow callers to pass 'fg' for text color; map to customtkinter's
        # 'text_color' when using CTkLabel.
        fg = kwargs.pop("fg", None)
        if not USE_CUSTOM:
            kwargs.setdefault("font", (Theme.FONT_FAMILY, Theme.BODY_SIZE))
            kwargs.setdefault("bg", Theme.BACKGROUND)
            if fg is not None:
                kwargs.setdefault("fg", fg)
        else:
            # customtkinter uses 'text_color' instead of 'fg'
            kwargs.setdefault("font", (Theme.FONT_FAMILY, Theme.BODY_SIZE))
            if fg is not None:
                kwargs.setdefault("text_color", fg)
        super().__init__(master, **kwargs)

# ==================== LOGIN SCREEN ====================

class LoginScreen:
    """Login screen"""
    
    def __init__(self, root, on_success):
        self.root = root
        self.on_success = on_success
        self.auth = AuthService()
        AuthService.initialize_admin()
        
        self.setup()
    
    def setup(self):
        """Setup login UI"""
        for w in self.root.winfo_children():
            w.destroy()
        
        self.root.geometry("400x300")
        
        # Container
        container = tk.Frame(self.root, bg=Theme.BACKGROUND)
        container.pack(expand=True, fill="both", padx=20, pady=20)
        
        # Title (colored)
        title = ModernLabel(container, text="🔐 Secure File Manager", font=(Theme.FONT_FAMILY, 20, "bold"), fg=Theme.SECONDARY)
        title.pack(pady=(0, 20))
        
        # Username
        tk.Label(container, text="Username", bg=Theme.BACKGROUND).pack(anchor="w")
        self.user_entry = ModernEntry(container)
        self.user_entry.pack(fill="x", pady=(0, 10))
        
        # Password
        tk.Label(container, text="Password", bg=Theme.BACKGROUND).pack(anchor="w")
        self.pass_entry = ModernEntry(container)
        self.pass_entry.pack(fill="x", pady=(0, 20))
        self.pass_entry.configure(show="●")
        
        # Login button
        login_btn = ModernButton(container, text="Login", command=self.login)
        login_btn.pack(fill="x", pady=(0, 10))
        
        # Bind Enter
        self.pass_entry.bind("<Return>", lambda e: self.login())
        
        # Info
        info = ModernLabel(container, text="Default: admin / admin123", font=(Theme.FONT_FAMILY, 10))
        info.pack(pady=(10, 0))
    
    def login(self):
        """Attempt login"""
        user = self.user_entry.get().strip()
        pwd = self.pass_entry.get().strip()
        
        if not user or not pwd:
            show_message("Error", "Enter username and password", "error")
            return
        
        ok, role = self.auth.authenticate(user, pwd)
        if ok:
            log_activity(user, "login", "-", "SUCCESS")
            self.on_success(user, role)
        else:
            log_activity(user, "login", "-", "FAILED")
            show_message("Error", "Invalid credentials", "error")

# ==================== MAIN APPLICATION ====================

class MainApp:
    """Main application"""
    
    def __init__(self, root, username: str, role: str):
        self.root = root
        self.username = username
        self.role = role
        self.file_service = FileService()
        
        self.setup()
    
    def setup(self):
        """Setup main UI"""
        for w in self.root.winfo_children():
            w.destroy()
        
        self.root.geometry("900x600")
        
        # Header
        header = tk.Frame(self.root, bg=Theme.PRIMARY, height=60)
        header.pack(fill="x")
        header.pack_propagate(False)
        
        tk.Label(header, text=f"👤 {self.username} ({self.role})", bg=Theme.PRIMARY, fg=Theme.WHITE, font=(Theme.FONT_FAMILY, 12)).pack(side="left", padx=20)
        
        btn_frame = tk.Frame(header, bg=Theme.PRIMARY)
        btn_frame.pack(side="right", padx=20)
        
        if self.role == "admin":
            ModernButton(btn_frame, text="⚙️ Admin", command=self.admin_panel).pack(side="left", padx=5)
        
        ModernButton(btn_frame, text="📤 Export", command=self.export).pack(side="left", padx=5)
        ModernButton(btn_frame, text="🚪 Logout", command=self.logout).pack(side="left", padx=5)
        
        # Main content
        content = tk.Frame(self.root, bg=Theme.BACKGROUND)
        content.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Left panel
        left = tk.Frame(content, bg=Theme.BACKGROUND)
        left.pack(side="left", fill="both", expand=True, padx=(0, 5))
        
        tk.Label(left, text="🔍 Files", bg=Theme.BACKGROUND, font=(Theme.FONT_FAMILY, 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        self.search_var = tk.StringVar()
        search = ModernEntry(left, textvariable=self.search_var)
        search.pack(fill="x", pady=(0, 5))
        self.search_var.trace("w", lambda *a: self.refresh_files())
        
        sb = tk.Scrollbar(left)
        sb.pack(side="right", fill="y")
        
        self.file_list = tk.Listbox(left, font=(Theme.FONT_FAMILY, 12), yscrollcommand=sb.set)
        self.file_list.pack(fill="both", expand=True)
        sb.configure(command=self.file_list.yview)
        
        self.refresh_files()
        
        # Right panel
        right = tk.Frame(content, bg=Theme.BACKGROUND)
        right.pack(side="right", fill="both", expand=True, padx=(5, 0))
        
        tk.Label(right, text="📋 Actions", bg=Theme.BACKGROUND, font=(Theme.FONT_FAMILY, 12, "bold")).pack(anchor="w", pady=(0, 5))
        
        ModernButton(right, text="📄 Create", command=self.create).pack(fill="x", pady=2)
        ModernButton(right, text="👁️ Read", command=self.read).pack(fill="x", pady=2)
        ModernButton(right, text="✏️ Update", command=self.update).pack(fill="x", pady=2)
        ModernButton(right, text="🗑️ Delete", command=self.delete).pack(fill="x", pady=2)
        
        tk.Label(right, text="📋 Logs", bg=Theme.BACKGROUND, font=(Theme.FONT_FAMILY, 12, "bold")).pack(anchor="w", pady=(10, 5))
        
        self.logs_text = tk.Text(right, font=(Theme.FONT_FAMILY, 10), height=15)
        self.logs_text.pack(fill="both", expand=True)
        self.logs_text.configure(state="disabled")
        
        self.update_logs()
    
    def refresh_files(self):
        """Refresh file list"""
        self.file_list.delete(0, tk.END)
        search = self.search_var.get()
        files = self.file_service.list_files(search)
        for f in files:
            self.file_list.insert(tk.END, f)
    
    def get_selected(self) -> Optional[str]:
        """Get selected file"""
        sel = self.file_list.curselection()
        return self.file_list.get(sel[0]) if sel else None
    
    def create(self):
        """Create file"""
        name = ask_string("Create", "Filename:")
        if not name:
            return

        # Notepad-style editor (large, monospace, horizontal+vertical scrollbars)
        w = tk.Toplevel(self.root)
        w.title(f"Create - {name}")
        w.geometry("900x600")

        # Menu bar (basic: File -> Save, Close)
        menubar = tk.Menu(w)
        filemenu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=filemenu)
        filemenu.add_command(label="Save", command=lambda: save_and_close())
        filemenu.add_command(label="Close", command=w.destroy)
        w.config(menu=menubar)

        h_scroll = tk.Scrollbar(w, orient="horizontal")
        h_scroll.pack(side="bottom", fill="x")
        v_scroll = tk.Scrollbar(w)
        v_scroll.pack(side="right", fill="y")

        editor = tk.Text(w, font=("Consolas", 12), wrap="none", xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)
        editor.pack(fill="both", expand=True)
        h_scroll.config(command=editor.xview)
        v_scroll.config(command=editor.yview)

        btn_frame = tk.Frame(w)
        btn_frame.pack(fill="x", pady=6)

        def save_and_close():
            content = editor.get("1.0", tk.END)
            if self.file_service.save_file(name, content, self.username):
                show_message("Success", f"File '{name}' created", "info")
                self.refresh_files()
                w.destroy()
            else:
                show_message("Error", "Failed to create file", "error")

        tk.Button(btn_frame, text="Save", command=save_and_close).pack(side="right", padx=6)
        tk.Button(btn_frame, text="Cancel", command=w.destroy).pack(side="right")
    
    def read(self):
        """Read file"""
        name = self.get_selected()
        if not name:
            show_message("Error", "Select a file", "error")
            return
        if not PermissionService.check_perm(self.username, name, "read"):
            show_message("Denied", "No read permission", "error")
            return
        content = self.file_service.read_file(name, self.username)
        if content:
            # Large read-only notepad-style viewer
            w = tk.Toplevel(self.root)
            w.title(f"View - {name}")
            w.geometry("1000x700")

            h_scroll = tk.Scrollbar(w, orient="horizontal")
            h_scroll.pack(side="bottom", fill="x")
            v_scroll = tk.Scrollbar(w)
            v_scroll.pack(side="right", fill="y")

            t = tk.Text(w, font=("Consolas", 12), wrap="none", xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)
            t.pack(fill="both", expand=True)
            h_scroll.config(command=t.xview)
            v_scroll.config(command=t.yview)
            t.insert("1.0", content)
            t.configure(state="disabled")
    
    def update(self):
        """Update file"""
        name = self.get_selected()
        if not name:
            show_message("Error", "Select a file", "error")
            return
        if not PermissionService.check_perm(self.username, name, "write"):
            show_message("Denied", "No write permission", "error")
            return
        current = self.file_service.read_file(name, self.username)
        if current is None:
            show_message("Error", "Cannot read file", "error")
            return
        # Notepad-style editor pre-filled for update
        w = tk.Toplevel(self.root)
        w.title(f"Update - {name}")
        w.geometry("1000x700")

        h_scroll = tk.Scrollbar(w, orient="horizontal")
        h_scroll.pack(side="bottom", fill="x")
        v_scroll = tk.Scrollbar(w)
        v_scroll.pack(side="right", fill="y")

        editor = tk.Text(w, font=("Consolas", 12), wrap="none", xscrollcommand=h_scroll.set, yscrollcommand=v_scroll.set)
        editor.pack(fill="both", expand=True)
        h_scroll.config(command=editor.xview)
        v_scroll.config(command=editor.yview)
        editor.insert("1.0", current)

        btn_frame = tk.Frame(w)
        btn_frame.pack(fill="x", pady=6)

        def save_and_close():
            new_content = editor.get("1.0", tk.END)
            if self.file_service.save_file(name, new_content, self.username):
                show_message("Success", "File updated", "info")
                w.destroy()
            else:
                show_message("Error", "Failed to update file", "error")

        tk.Button(btn_frame, text="Save", command=save_and_close).pack(side="right", padx=6)
        tk.Button(btn_frame, text="Cancel", command=w.destroy).pack(side="right")
    
    def delete(self):
        """Delete file"""
        name = self.get_selected()
        if not name:
            show_message("Error", "Select a file", "error")
            return
        if not PermissionService.check_perm(self.username, name, "delete"):
            show_message("Denied", "No delete permission", "error")
            return
        if ask_confirmation("Confirm", f"Delete '{name}'?"):
            if self.file_service.delete_file(name, self.username):
                show_message("Success", "File deleted", "info")
                self.refresh_files()
            else:
                show_message("Error", "Failed to delete", "error")
    
    def update_logs(self):
        """Update logs display"""
        self.logs_text.configure(state="normal")
        self.logs_text.delete("1.0", tk.END)
        logs = LogService.get_recent(20)
        self.logs_text.insert("1.0", logs)
        self.logs_text.configure(state="disabled")
        self.root.after(5000, self.update_logs)
    
    def admin_panel(self):
        """Open admin panel"""
        if self.role != "admin":
            show_message("Denied", "Admin only", "error")
            return
        
        w = tk.Toplevel(self.root)
        w.title("Admin Panel")
        w.geometry("600x400")
        
        nb = ttk.Notebook(w)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Users tab
        user_frame = tk.Frame(nb)
        nb.add(user_frame, text="Users")
        
        tk.Label(user_frame, text="Manage Users").pack(pady=10)
        
        btn_frame = tk.Frame(user_frame)
        btn_frame.pack(pady=10)
        
        def add_user():
            un = ask_string("Add User", "Username:")
            if not un:
                return
            pw = ask_string("Password", "Password:")
            if not pw:
                return
            ok, msg = AuthService().create_user(un, pw, "user")
            show_message("Result", msg, "info" if ok else "error")
        
        ModernButton(btn_frame, text="Add User", command=add_user).pack(side="left", padx=5)
        
        # Permissions tab
        perm_frame = tk.Frame(nb)
        nb.add(perm_frame, text="Permissions")
        
        tk.Label(perm_frame, text="Manage Permissions").pack(pady=10)
        
        def set_perms():
            users = AuthService.load_users()
            files = self.file_service.list_files()
            
            if not users or not files:
                show_message("Info", "No users or files to manage", "info")
                return
            
            user = ask_string("Set Permission", "Username:", list(users.keys())[0])
            if not user:
                return
            
            filename = ask_string("Set Permission", "Filename:", files[0] if files else "")
            if not filename:
                return
            
            PermissionService.set_perm(user, filename, read=True, write=False, delete=False)
            show_message("Success", f"Set read permission for {user} on {filename}", "info")
        
        ModernButton(perm_frame, text="Set Permissions", command=set_perms).pack(pady=10)
    
    def export(self):
        """Export logs"""
        if USE_PDF:
            ok, msg = LogService.export_pdf()
            if ok:
                show_message("Success", msg, "info")
                return
        
        ok, msg = LogService.export_txt()
        show_message("Success" if ok else "Error", msg, "info" if ok else "error")
    
    def logout(self):
        """Logout"""
        log_activity(self.username, "logout", "-", "SUCCESS")
        LoginScreen(self.root, lambda u, r: MainApp(self.root, u, r))

# ==================== MAIN ENTRY POINT ====================

class Application:
    """Main application controller"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Manager")
        self.root.geometry("900x600")
        
        LoginScreen(self.root, self.show_main)
    
    def show_main(self, username: str, role: str):
        """Show main application"""
        MainApp(self.root, username, role)

if __name__ == "__main__":
    root = tk.Tk()
    app = Application(root)
    root.mainloop()
