import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import time
import random
import re
import os


HOST = '127.0.0.1'
PORT = 12345

clients = []
online_users = []
user_colors = {}

clients_lock = threading.Lock()
online_users_lock = threading.Lock()


def broadcast(message, client_socket):
    for client in clients:
        if client != client_socket:
            try:
                client.send(message)
            except:
                remove_client(client)

def remove_client(client_socket):
    with clients_lock:
        if client_socket in clients:
            clients.remove(client_socket)

def remove_user(username):
    with online_users_lock:
        if username in online_users:
            online_users.remove(username)
            update_online_users()
            if username in user_colors:
                del user_colors[username]

def add_user(username):
    with online_users_lock:
        if username not in online_users:
            online_users.append(username)
            update_online_users()
            if username not in user_colors:
                user_colors[username] = '#{:06x}'.format(random.randint(0, 0xFFFFFF))
                chat_log.tag_config(username, foreground=user_colors[username])

def handle_client(client_socket, client_address):
    ip = client_address[0]
    update_chat(f"اتصال از {ip} برقرار شد.\n")

    try:
        username = client_socket.recv(1024).decode('utf-8')
        add_user(username)
        update_chat(f"{username} به سرور متصل شد.\n")

        while True:
            message = client_socket.recv(1024)
            if not message:
                break

            timestamp = time.strftime("%H:%M:%S")
            formatted_message = f"[{timestamp}] {username}: {message.decode('utf-8')}\n".encode('utf-8')

            update_chat(formatted_message.decode('utf-8'))
            broadcast(formatted_message, client_socket)

    except Exception as e:
        update_chat(f"خطا در ارتباط با {username}: {e}\n")
    finally:
        remove_user(username)
        update_chat(f"{username} از سرور جدا شد.\n")
        remove_client(client_socket)
        client_socket.close()

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.bind((HOST, PORT))
    except socket.error as e:
        update_chat(str(e) + "\n")
        return

    server_socket.listen()
    update_chat(f"سرور در حال گوش دادن در {HOST}:{PORT}...\n")

    while True:
        client_socket, client_address = server_socket.accept()
        with clients_lock:
            clients.append(client_socket)

        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()


def update_chat(message):
    chat_log.config(state=tk.NORMAL)

    match = re.match(r"\[(\d{2}:\d{2}:\d{2})\] (\w+): (.*)", message)
    if match:
        timestamp, username, msg = match.groups()
        tag = username if username in user_colors else None
        chat_log.insert(tk.END, f"[{timestamp}] {username}: {msg}\n", tag)
    else:
        chat_log.insert(tk.END, message)

    chat_log.config(state=tk.DISABLED)
    chat_log.see(tk.END)

def update_online_users():
    online_users_log.config(state=tk.NORMAL)
    online_users_log.delete('1.0', tk.END)
    for user in online_users:
        online_users_log.insert(tk.END, user + '\n')
    online_users_log.config(state=tk.DISABLED)

def clear_chat():
    chat_log.config(state=tk.NORMAL)
    chat_log.delete('1.0', tk.END)
    chat_log.config(state=tk.DISABLED)

def send_message():
    message = message_entry.get().strip()
    if message:
        timestamp = time.strftime("%H:%M:%S")
        full_message = f"[{timestamp}] Server: {message}\n"
        update_chat(full_message)
        broadcast(full_message.encode('utf-8'), None)
        message_entry.delete(0, tk.END)

def on_closing():
    if messagebox.askokcancel("خروج", "آیا مطمئن هستید که می‌خواهید خارج شوید؟"):
        root.destroy()
        os._exit(0)

def start_server_gui():
    global chat_log, message_entry, root, online_users_log

    root = tk.Tk()
    root.title("Server Chat")
    root.geometry("850x450")

    chat_log = scrolledtext.ScrolledText(root, height=15, width=50, bg="#f0f0f0", fg="black", font=("Arial", 10))
    chat_log.pack(padx=10, pady=10, fill=tk.BOTH, expand=True, side=tk.LEFT)

    online_users_frame = tk.Frame(root)
    online_users_frame.pack(side=tk.RIGHT, padx=10, pady=10, fill=tk.Y)

    online_users_label = tk.Label(online_users_frame, text="کاربران آنلاین:", font=("Arial", 10, "bold"))
    online_users_label.pack()

    online_users_log = scrolledtext.ScrolledText(online_users_frame, state=tk.DISABLED, height=15, width=20, bg="#f0f0f0", fg="black", font=("Arial", 10))
    online_users_log.pack()

    bottom_frame = tk.Frame(root)
    bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    message_entry = tk.Entry(bottom_frame, font=("Arial", 12))
    message_entry.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
    bottom_frame.columnconfigure(0, weight=1)

    send_button = tk.Button(bottom_frame, text="✉️ ارسال", command=send_message, bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
    send_button.grid(row=0, column=1, padx=5)

    clear_button = tk.Button(bottom_frame, text="🧹 پاک کردن", command=clear_chat, bg="#f44336", fg="white", font=("Arial", 10))
    clear_button.grid(row=0, column=2, padx=5)

    root.protocol("WM_DELETE_WINDOW", on_closing)

    server_thread = threading.Thread(target=start_server)
    server_thread.daemon = True
    server_thread.start()

    root.mainloop()

if __name__ == "__main__":
    start_server_gui()
