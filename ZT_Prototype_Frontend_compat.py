import os 
# to get the file address and perform edits on it.
import json
#to temporarily store the key and encrypted data during the process of encryption. 
import base64
#to aid in the process of key and iv generation and binary data transmutation.
import tkinter as tk
#To create the dialog box and user interface
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
#to convert original binary data into encrypted data.
from cryptography.hazmat.backends import default_backend
#cryptography modules to run the algortihm
from cryptography.hazmat.primitives import padding

# encrypt

def encrypt_and_replace(input_file, key_store):
    try:
        key = os.urandom(32) #Used to run AES Algorithm  
        iv = os.urandom(16)  #Used to run CBC mode
        with open(input_file, 'rb') as f:
            data = f.read()
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        with open(input_file, 'wb') as f:
            f.write(iv + encrypted_data)
        # save key in temp
        key_entry = {"file": input_file, "key": base64.b64encode(key).decode('utf-8')}
        with open(key_store, 'a') as f:
            f.write(json.dumps(key_entry) + "\n")
        # drop key
        with open(key_store, 'w') as f:
            f.write("")
        os.remove(input_file)
        return True, f"File '{os.path.basename(input_file)}' secured and deleted permanently."
    except Exception as e:
        return False, str(e)

def encrypt_and_replace_folder(folder_path, key_store):
    try:
        total_files = 0
        for root, _, files in os.walk(folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                success, msg = encrypt_and_replace(file_path, key_store)
                if not success:
                    return False, msg
                total_files += 1
        if total_files == 0:
            return False, "No files found in the selected folder."
        return True, f"Folder '{os.path.basename(folder_path)}' secured and all files deleted permanently."
    except Exception as e:
        return False, str(e)

# gui fn
def choose_file():
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    success, msg = encrypt_and_replace(file_path, "key_store.json")
    if success:
        messagebox.showinfo("Success", msg)
    else:
        messagebox.showerror("Error", msg)

def choose_folder():
    folder_path = filedialog.askdirectory()
    if not folder_path:
        return
    success, msg = encrypt_and_replace_folder(folder_path, "key_store.json")
    if success:
        messagebox.showinfo("Success", msg)
    else:
        messagebox.showerror("Error", msg)

def select_action(action):
    if action == "File":
        choose_file()
    elif action == "Folder":
        choose_folder()

# gui
def main():
    root = tk.Tk()
    root.title("Secure Data Annihilator")
    root.geometry("400x200")

    label = tk.Label(root, text="Select a File or Folder to Secure & Delete", font=("Arial", 12))
    label.pack(pady=20)

#Dropdown fn
    options = ["File", "Folder"]
    selected = tk.StringVar()
    selected.set("Choose...")

    dropdown = tk.OptionMenu(root, selected, *options, command=select_action)
    dropdown.config(width=20, height=2, font=("Arial", 10))
    dropdown.pack(pady=30)

    root.mainloop()

if __name__ == "__main__":
    main()
