import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib
import os
import pyperclip
import webbrowser  # To open the URL in a browser

# Function to calculate hash based on the selected algorithm
def calculate_hash(filename, algorithm):
    try:
        hash_func = getattr(hashlib, algorithm)()
        with open(filename, "rb") as file:
            while chunk := file.read(4096):  # Read file in chunks to handle large files
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Error reading file: {e}")
        return None

# Function to handle file selection
def select_file():
    file_path = filedialog.askopenfilename(title="Select File")
    if file_path:
        file_path_var.set(file_path)

# Function to compute hash and display it
def compute_hash():
    file_path = file_path_var.get()
    if not file_path or not os.path.isfile(file_path):
        messagebox.showwarning("Warning", "Please select a valid file.")
        return

    algorithm = hash_algorithm_var.get()
    computed_hash = calculate_hash(file_path, algorithm)
    if computed_hash:
        computed_hash_var.set(computed_hash)

# Function to compare computed and known hashes
def compare_hash():
    known_hash = known_hash_var.get().strip()
    computed_hash = computed_hash_var.get()

    if not known_hash:
        messagebox.showwarning("Warning", "Please enter a known hash value to compare.")
        return

    if computed_hash == known_hash:
        messagebox.showinfo("Match", "Hashes match!")
    else:
        messagebox.showinfo("No Match", "Hashes do not match.")

# Function to copy the computed hash to clipboard
def copy_to_clipboard():
    computed_hash = computed_hash_var.get()
    if computed_hash:
        pyperclip.copy(computed_hash)
        messagebox.showinfo("Copied", "Computed hash copied to clipboard.")

# Function to export computed hash to a file
def export_hash():
    computed_hash = computed_hash_var.get()
    if not computed_hash:
        messagebox.showwarning("Warning", "No hash computed to export.")
        return

    save_path = filedialog.asksaveasfilename(
        title="Save Hash As", 
        defaultextension=".txt", 
        filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")]
    )
    if save_path:
        try:
            with open(save_path, "w") as file:
                file.write(f"File: {file_path_var.get()}\n")
                file.write(f"Algorithm: {hash_algorithm_var.get().upper()}\n")
                file.write(f"Hash: {computed_hash}\n")
            messagebox.showinfo("Success", "Hash exported successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving hash: {e}")

# Function to open the GitHub link
def open_github():
    webbrowser.open("https://github.com/1-moxiu")

# GUI Setup
app = tk.Tk()
app.title("File Hash Matcher")
app.geometry("600x463")

# File selection
file_path_var = tk.StringVar()
tk.Label(app, text="Selected File:").pack(anchor="w", padx=10, pady=(10, 0))
tk.Entry(app, textvariable=file_path_var, width=60, state="readonly").pack(padx=10)
tk.Button(app, text="Select File", command=select_file).pack(pady=5)

# Hash algorithm selection
hash_algorithm_var = tk.StringVar(value="sha256")
tk.Label(app, text="Select Hash Algorithm:").pack(anchor="w", padx=10)
tk.OptionMenu(app, hash_algorithm_var, "md5", "sha1", "sha256", "sha512").pack(pady=5)

# Compute hash
computed_hash_var = tk.StringVar()
tk.Label(app, text="Computed Hash:").pack(anchor="w", padx=10, pady=(10, 0))
tk.Entry(app, textvariable=computed_hash_var, width=60, state="readonly").pack(padx=10)
tk.Button(app, text="Compute Hash", command=compute_hash).pack(pady=5)

# Known hash input for comparison
known_hash_var = tk.StringVar()
tk.Label(app, text="Known Hash (for comparison):").pack(anchor="w", padx=10, pady=(10, 0))
tk.Entry(app, textvariable=known_hash_var, width=60).pack(padx=10)
tk.Button(app, text="Compare Hashes", command=compare_hash).pack(pady=5)

# Extra utilities
tk.Button(app, text="Copy to Clipboard", command=copy_to_clipboard).pack(pady=5)
tk.Button(app, text="Export Hash", command=export_hash).pack(pady=5)

# Adding the "Made by Moxiu" and "On GitHub:" labels with a clickable link

# "Made by Moxiu"
tk.Label(app, text="Made by Moxiu", font=("Arial", 10, "bold")).pack(anchor="w", padx=10)

# "On GitHub:" label
tk.Label(app, text="On GitHub:", font=("Arial", 10)).pack(anchor="w", padx=10)

# GitHub clickable link
github_link = tk.Label(app, text="https://github.com/1-moxiu", fg="blue", cursor="hand2")
github_link.pack(anchor="w", padx=10, pady=(0, 10))

# Binding the GitHub link to open in a web browser
github_link.bind("<Button-1>", lambda e: open_github())

# Run the application
app.mainloop()
