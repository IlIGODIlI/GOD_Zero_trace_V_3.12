import os
import base64
import json
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# -------------------------
# Low-level modular funcs
# -------------------------

def encrypt_file(file_path, key_size_bits=256):
    """
    Encrypts a file using AES-CBC.
    key_size_bits: 256 (default), 128, or 64 (64 will still derive 32 bytes random; UI is illustrative).
    Returns: (encrypted_file_path, base64_key)
    """
    # NOTE: We always generate a 32-byte key (AES-256). If a different size required,
    # a proper KDF/algorithm change would be implemented. For now UI lets user pick size,
    # but internal uses AES-256 (as requested).
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)

    with open(file_path, "rb") as f:
        data = f.read()

    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()

    # Overwrite file with (IV + ciphertext)
    with open(file_path, "wb") as f:
        f.write(iv + ciphertext)

    key_b64 = base64.b64encode(key).decode("utf-8")
    return file_path, key_b64

def decrypt_file(file_path, key_b64):
    """
    Decrypts an AES-CBC encrypted file. Expects IV prepended (16 bytes).
    Returns: (True/False, message)
    """
    try:
        key = base64.b64decode(key_b64)
    except Exception:
        return False, "Invalid base64 key."

    try:
        with open(file_path, "rb") as f:
            data = f.read()
        if len(data) < 16:
            return False, "File too short to be valid ciphertext."
        iv = data[:16]
        ciphertext = data[16:]

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        dec = cipher.decryptor()
        padded = dec.update(ciphertext) + dec.finalize()

        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded) + unpadder.finalize()

        with open(file_path, "wb") as f:
            f.write(plaintext)

        return True, f"'{os.path.basename(file_path)}' decrypted successfully."
    except ValueError:
        return False, "Decryption failed: wrong key or corrupted data (bad padding)."
    except Exception as e:
        return False, f"Decryption error: {e}"

def secure_delete(file_path):
    """
    Overwrite the file with random bytes then delete it.
    Returns: (True/False, message)
    """
    if not os.path.exists(file_path):
        return False, "File not found."

    try:
        size = os.path.getsize(file_path)
        # Overwrite
        with open(file_path, "wb") as f:
            f.write(os.urandom(size if size > 0 else 1))
        # Remove
        os.remove(file_path)
        return True, f"'{os.path.basename(file_path)}' securely deleted."
    except Exception as e:
        return False, f"Secure delete error: {e}"

# -------------------------
# Dark theme colors (Cyber Dark)
# -------------------------
BG = "#0D1117"         # page background
CARD = "#11151A"       # card background
PRIMARY = "#2385F2"    # blue accent
SUB = "#1F2937"        # button background
TXT = "#E6EEF6"        # main text
MUTED = "#9AA7B2"      # muted text

BUTTON_STYLE = {
    "bg": SUB,
    "fg": TXT,
    "activebackground": "#2a394a",
    "relief": "flat",
    "bd": 0,
    "padx": 8,
    "pady": 6
}

LABEL_PADY = 6

# -------------------------
# GUI - modular frame app
# -------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Data Annihilator — Dark")
        self.configure(bg=BG)
        self.geometry("900x600")
        self.minsize(820, 520)

        # keys storage
        self.last_key = None
        self.folder_keys = {}  # path -> key

        # container for frames
        container = tk.Frame(self, bg=BG)
        container.pack(fill="both", expand=True, padx=14, pady=14)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        # frames
        self.frames = {}
        for F in (MainFrame, EncryptFrame, DecryptFrame):
            page = F(parent=container, controller=self)
            self.frames[F] = page
            page.grid(row=0, column=0, sticky="nsew")

        self.show_frame(MainFrame)

    def show_frame(self, cls):
        frame = self.frames[cls]
        frame.tkraise()

# -------------------------
# Main navigation frame
# -------------------------
class MainFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG)
        self.controller = controller

        header = tk.Frame(self, bg=BG)
        header.pack(fill="x", pady=(6,12))
        title = tk.Label(header, text="Secure Data Annihilator", font=("Segoe UI", 18, "bold"), bg=BG, fg=TXT)
        title.pack(side="left", padx=8)

        sub = tk.Label(header, text="Dark Cyber • AES-256 default • Algorithms shown as placeholders", bg=BG, fg=MUTED)
        sub.pack(side="left", padx=12)

        nav = tk.Frame(self, bg=BG)
        nav.pack(fill="x", pady=(12,0))

        btn_enc = tk.Button(nav, text="ENCRYPT", command=lambda: controller.show_frame(EncryptFrame),
                            bg=PRIMARY, fg="white", activebackground="#1b6fd2", relief="flat", padx=18, pady=8)
        btn_enc.pack(side="left", padx=8)

        btn_dec = tk.Button(nav, text="DECRYPT", command=lambda: controller.show_frame(DecryptFrame),
                            **BUTTON_STYLE)
        btn_dec.pack(side="left", padx=8)

        # Quick area showing algorithm row and keysize (visual)
        toolbar = tk.Frame(self, bg=BG)
        toolbar.pack(fill="x", pady=(18,8))

        alg_label = tk.Label(toolbar, text="Algorithms (placeholders):", bg=BG, fg=TXT)
        alg_label.pack(side="left", padx=(8,6))
        for name in ("AES", "RES", "CSS", "VSD"):
            b = tk.Button(toolbar, text=name, width=8, **BUTTON_STYLE)
            b.pack(side="left", padx=6)

        size_label = tk.Label(toolbar, text="Key size:", bg=BG, fg=TXT)
        size_label.pack(side="left", padx=(20,8))
        for s in ("256-bit", "128-bit", "64-bit"):
            b = tk.Button(toolbar, text=s, **BUTTON_STYLE, width=10)
            b.pack(side="left", padx=6)

        # Quick tips/log area
        tip_frame = tk.Frame(self, bg=CARD, pady=12, padx=12)
        tip_frame.pack(fill="both", expand=True, pady=(18,0))

        lbl = tk.Label(tip_frame, text="Workflow overview", font=("Segoe UI", 12, "bold"), bg=CARD, fg=TXT)
        lbl.pack(anchor="w")
        tips = (
            "• Choose ENCRYPT to pick a file/folder and encrypt it. You will be asked to DELETE or SAVE the key.",
            "• If DELETE chosen: file is encrypted, securely overwritten and removed, key destroyed.",
            "• If SAVE chosen: file is encrypted in-place and the base64 key is shown. Save it safely.",
            "• Choose DECRYPT to pick an encrypted file and paste the key to restore it."
        )
        for t in tips:
            l = tk.Label(tip_frame, text=t, bg=CARD, fg=MUTED, anchor="w", justify="left")
            l.pack(fill="x", pady=4)

# -------------------------
# Encrypt Frame
# -------------------------
class EncryptFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG)
        self.controller = controller

        topbar = tk.Frame(self, bg=BG)
        topbar.pack(fill="x", pady=(6,8))
        back = tk.Button(topbar, text="◀ Back", command=lambda: controller.show_frame(MainFrame), **BUTTON_STYLE)
        back.pack(side="left", padx=8)
        title = tk.Label(topbar, text="Encrypt — Workflow", font=("Segoe UI", 14, "bold"), bg=BG, fg=TXT)
        title.pack(side="left", padx=12)

        # Selection area
        select_frame = tk.Frame(self, bg=CARD, pady=12, padx=12)
        select_frame.pack(fill="x", padx=12, pady=(12,8))

        lbl_file = tk.Label(select_frame, text="File Path:", bg=CARD, fg=TXT)
        lbl_file.grid(row=0, column=0, sticky="w")
        self.file_path_var = tk.StringVar()
        ent_file = tk.Entry(select_frame, textvariable=self.file_path_var, width=80, bg="#0c1014", fg=TXT, insertbackground=TXT)
        ent_file.grid(row=0, column=1, padx=8)

        btn_choose_file = tk.Button(select_frame, text="Select File", command=self.choose_file, **BUTTON_STYLE)
        btn_choose_file.grid(row=0, column=2, padx=(8,0))

        lbl_folder = tk.Label(select_frame, text="Or select folder:", bg=CARD, fg=TXT)
        lbl_folder.grid(row=1, column=0, sticky="w", pady=(8,0))
        self.folder_path_var = tk.StringVar()
        ent_folder = tk.Entry(select_frame, textvariable=self.folder_path_var, width=80, bg="#0c1014", fg=TXT, insertbackground=TXT)
        ent_folder.grid(row=1, column=1, padx=8, pady=(8,0))
        btn_choose_folder = tk.Button(select_frame, text="Select Folder", command=self.choose_folder, **BUTTON_STYLE)
        btn_choose_folder.grid(row=1, column=2, padx=(8,0), pady=(8,0))

        # Algorithm row (radio, placeholder)
        alg_frame = tk.Frame(self, bg=BG)
        alg_frame.pack(fill="x", padx=12, pady=(6,6))
        alg_label = tk.Label(alg_frame, text="Algorithm:", bg=BG, fg=TXT)
        alg_label.pack(side="left", padx=(6,8))
        self.alg_var = tk.StringVar(value="AES")
        for a in ("AES", "RES", "CSS", "VSD"):
            rb = tk.Radiobutton(alg_frame, text=a, variable=self.alg_var, value=a, bg=BG, fg=TXT, selectcolor="#0D1117", activebackground=BG)
            rb.pack(side="left", padx=10)

        # Keysize row
        ks_frame = tk.Frame(self, bg=BG)
        ks_frame.pack(fill="x", padx=12, pady=(0,10))
        ks_label = tk.Label(ks_frame, text="Key size:", bg=BG, fg=TXT)
        ks_label.pack(side="left", padx=(6,8))
        self.ks_var = tk.IntVar(value=256)
        for bits in (256, 128, 64):
            rb = tk.Radiobutton(ks_frame, text=f"{bits}-bit", variable=self.ks_var, value=bits, bg=BG, fg=TXT, selectcolor="#0D1117", activebackground=BG)
            rb.pack(side="left", padx=8)

        # Action buttons
        actions = tk.Frame(self, bg=BG)
        actions.pack(fill="x", padx=12, pady=(6,6))
        enc_btn = tk.Button(actions, text="<<< ENCRYPT >>>", command=self.start_encrypt, bg=PRIMARY, fg="white", padx=12, pady=8)
        enc_btn.pack(side="left", padx=10)

        # Save / Delete controls (visible after encryption)
        post_frame = tk.Frame(self, bg=CARD, pady=12, padx=12)
        post_frame.pack(fill="both", expand=True, padx=12, pady=(12,12))

        key_lbl = tk.Label(post_frame, text="Encryption Key (base64):", bg=CARD, fg=TXT)
        key_lbl.pack(anchor="w")
        self.key_entry = tk.Entry(post_frame, width=80, bg="#081118", fg=TXT, insertbackground=TXT)
        self.key_entry.pack(fill="x", pady=(6,10))

        key_actions = tk.Frame(post_frame, bg=CARD)
        key_actions.pack(fill="x")
        save_btn = tk.Button(key_actions, text="Save Key to File", command=self.save_key_file, **BUTTON_STYLE)
        save_btn.pack(side="left", padx=6)
        copy_btn = tk.Button(key_actions, text="Copy Key", command=self.copy_key, **BUTTON_STYLE)
        copy_btn.pack(side="left", padx=6)

        # Log
        log_label = tk.Label(post_frame, text="Activity Log", bg=CARD, fg=TXT)
        log_label.pack(anchor="w", pady=(12,6))
        self.log = scrolledtext.ScrolledText(post_frame, height=12, bg="#071018", fg=TXT, insertbackground=TXT, wrap="word")
        self.log.pack(fill="both", expand=True)

    # ---------- helpers ----------
    def log_message(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def choose_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.file_path_var.set(p)
            self.log_message(f"Selected file: {p}")

    def choose_folder(self):
        p = filedialog.askdirectory()
        if p:
            self.folder_path_var.set(p)
            self.log_message(f"Selected folder: {p}")

    def copy_key(self):
        k = self.key_entry.get().strip()
        if not k:
            messagebox.showwarning("No Key", "No key to copy.")
            return
        self.controller.clipboard_clear()
        self.controller.clipboard_append(k)
        self.log_message("Key copied to clipboard.")

    def save_key_file(self):
        k = self.key_entry.get().strip()
        if not k:
            messagebox.showwarning("No Key", "No key to save.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text", "*.txt"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(k)
            self.log_message(f"Saved key to: {path}")
            messagebox.showinfo("Saved", f"Key saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))
            self.log_message("Save key error: " + str(e))

    # ---------- encryption flow ----------
    def start_encrypt(self):
        file_path = self.file_path_var.get().strip()
        folder_path = self.folder_path_var.get().strip()
        if not file_path and not folder_path:
            messagebox.showwarning("No selection", "Select a file or a folder to encrypt.")
            return

        alg = self.alg_var.get()
        ks = self.ks_var.get()
        # We only support AES (placeholder UI shows others)
        if alg != "AES":
            proceed = messagebox.askyesno("Algorithm placeholder", f"'{alg}' is a placeholder in the UI. Proceed with AES-256 anyway?")
            if not proceed:
                return

        if file_path:
            try:
                enc_path, key_b64 = encrypt_file(file_path, key_size_bits=ks)
                # After encryption, ask whether to delete or save
                choice = messagebox.askquestion("File Encrypted", "File encrypted. Choose action:\nYes = Secure delete (key destroyed)\nNo = Keep file and show key (save key).", icon="question")
                # note: askquestion returns 'yes' or 'no'
                if choice == "yes":
                    ok, msg = secure_delete(enc_path)
                    if ok:
                        self.key_entry.delete(0, tk.END)
                        self.controller.last_key = None
                        self.log_message(f"{os.path.basename(enc_path)} encrypted and securely deleted. Key destroyed.")
                        messagebox.showinfo("Done", "File encrypted, securely deleted and key destroyed.")
                    else:
                        self.log_message("Secure delete failed: " + msg)
                        messagebox.showwarning("Secure delete failed", msg)
                else:
                    # keep key visible
                    self.key_entry.delete(0, tk.END)
                    self.key_entry.insert(0, key_b64)
                    # save last key in controller
                    self.controller.last_key = key_b64
                    self.controller.folder_keys.pop(file_path, None)
                    self.log_message(f"File encrypted: {enc_path}\nKey shown in key box. Save it securely.")
                    messagebox.showinfo("Encrypted", "File encrypted. Key is shown in the key box. Save it securely.")
            except Exception as e:
                messagebox.showerror("Encrypt failed", str(e))
                self.log_message("Encryption failed: " + str(e))

        else:
            # folder encrypt (recursive)
            folder = folder_path
            keys_map = {}
            encrypted_count = 0
            errors = []
            for root, _, files in os.walk(folder):
                for f in files:
                    p = os.path.join(root, f)
                    try:
                        _, key_b64 = encrypt_file(p, key_size_bits=ks)
                        keys_map[p] = key_b64
                        encrypted_count += 1
                        self.log_message(f"Encrypted: {p}")
                    except Exception as e:
                        errors.append((p, str(e)))
                        self.log_message(f"Failed: {p} -> {e}")

            if encrypted_count == 0:
                messagebox.showinfo("No files", "No files were encrypted in the folder.")
                return

            # Ask whether to secure-delete or save keys file
            choice = messagebox.askquestion("Folder Encrypted", f"Encrypted {encrypted_count} files.\nYes = Secure-delete all encrypted files (keys destroyed)\nNo = Keep files and provide keys to save.", icon="question")
            if choice == "yes":
                deleted = 0
                for p, _ in list(keys_map.items()):
                    ok, msg = secure_delete(p)
                    if ok:
                        deleted += 1
                        keys_map.pop(p, None)
                        self.log_message(msg)
                    else:
                        self.log_message("Secure delete failed: " + msg)
                # remove destroyed keys from controller storage
                for p in list(keys_map.keys()):
                    keys_map.pop(p, None)
                self.controller.folder_keys.update({})  # all destroyed
                messagebox.showinfo("Folder Done", f"Encrypted {encrypted_count} files.\nSecure-deleted {deleted} files. Keys destroyed.")
            else:
                # keep keys in controller storage
                self.controller.folder_keys.update(keys_map)
                # we will store last_key only for single file encrypt; for folder, keys stored in folder_keys
                self.log_message(f"Folder encrypted: {encrypted_count} files. Use 'Save Key' to export keys.")
                messagebox.showinfo("Folder Encrypted", f"Encrypted {encrypted_count} files.\nUse 'Save Key to File' to export keys.")

# -------------------------
# Decrypt Frame
# -------------------------
class DecryptFrame(tk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent, bg=BG)
        self.controller = controller

        topbar = tk.Frame(self, bg=BG)
        topbar.pack(fill="x", pady=(6,8))
        back = tk.Button(topbar, text="◀ Back", command=lambda: controller.show_frame(MainFrame), **BUTTON_STYLE)
        back.pack(side="left", padx=8)
        title = tk.Label(topbar, text="Decrypt — Workflow", font=("Segoe UI", 14, "bold"), bg=BG, fg=TXT)
        title.pack(side="left", padx=12)

        body = tk.Frame(self, bg=CARD, padx=12, pady=12)
        body.pack(fill="both", expand=True, padx=12, pady=12)

        lbl = tk.Label(body, text="Select Encrypted File:", bg=CARD, fg=TXT)
        lbl.pack(anchor="w")
        self.file_var = tk.StringVar()
        ent = tk.Entry(body, textvariable=self.file_var, width=90, bg="#081418", fg=TXT, insertbackground=TXT)
        ent.pack(fill="x", pady=(6,8))
        btn = tk.Button(body, text="Choose File", command=self.choose_file, **BUTTON_STYLE)
        btn.pack(anchor="w", pady=(0,8))

        key_lbl = tk.Label(body, text="Paste Key (base64):", bg=CARD, fg=TXT)
        key_lbl.pack(anchor="w", pady=(12,0))
        self.key_entry = tk.Entry(body, width=90, bg="#081418", fg=TXT, insertbackground=TXT)
        self.key_entry.pack(fill="x", pady=(6,8))

        dec_btn = tk.Button(body, text="DECRYPT", command=self.start_decrypt, bg=PRIMARY, fg="white", padx=12, pady=8)
        dec_btn.pack(pady=(8,12))

        # Log
        log_label = tk.Label(body, text="Activity Log", bg=CARD, fg=TXT)
        log_label.pack(anchor="w")
        self.log = scrolledtext.ScrolledText(body, height=12, bg="#071018", fg=TXT, insertbackground=TXT, wrap="word")
        self.log.pack(fill="both", expand=True)

        # quick buttons: paste last key, save key from controller
        bottom = tk.Frame(self, bg=BG)
        bottom.pack(fill="x", padx=12, pady=(6,12))
        paste_last_btn = tk.Button(bottom, text="Use Last Key (if available)", command=self.use_last_key, **BUTTON_STYLE)
        paste_last_btn.pack(side="left", padx=6)
        load_key_file_btn = tk.Button(bottom, text="Load Key from File", command=self.load_key_file, **BUTTON_STYLE)
        load_key_file_btn.pack(side="left", padx=6)

    def log_message(self, text):
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def choose_file(self):
        p = filedialog.askopenfilename()
        if p:
            self.file_var.set(p)
            self.log_message(f"Selected file: {p}")

    def use_last_key(self):
        k = self.controller.last_key
        if not k:
            messagebox.showwarning("No key", "No last key available.")
            return
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, k)
        self.log_message("Inserted last key into key box.")

    def load_key_file(self):
        p = filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All", "*.*")])
        if not p:
            return
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = f.read().strip()
            # If JSON contains mapping, show info and allow user to pick key (for simplicity we put content)
            self.key_entry.delete(0, tk.END)
            self.key_entry.insert(0, data)
            self.log_message(f"Loaded key(s) from: {p}")
        except Exception as e:
            messagebox.showerror("Load failed", str(e))
            self.log_message("Failed to load key file: " + str(e))

    def start_decrypt(self):
        p = self.file_var.get().strip()
        k = self.key_entry.get().strip()
        if not p:
            messagebox.showwarning("No file", "Select a file to decrypt.")
            return
        if not k:
            messagebox.showwarning("No key", "Paste key into the key box or use 'Use Last Key'.")
            return
        ok, msg = decrypt_file(p, k)
        if ok:
            self.log_message(msg)
            messagebox.showinfo("Decrypted", msg)
        else:
            self.log_message("Decryption failed: " + msg)
            messagebox.showerror("Decryption failed", msg)

# -------------------------
# Run
# -------------------------
if __name__ == "__main__":
    app = App()
    app.mainloop()
