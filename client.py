import socket
import tkinter as tk
from tkinter import scrolledtext, simpledialog, messagebox
import threading


HOST = '127.0.0.1'  
PORT = 12345        

class ChatClient:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.socket = None
        self.username = None
        self.running = True

        self.root = tk.Tk()
        self.root.title("Chat Client")
        self.root.geometry("600x400")  

      
        self.chat_log = scrolledtext.ScrolledText(self.root, height=15, width=70, bg="#f0f0f0", fg="black")
        self.chat_log.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)
        self.chat_log.tag_config('sent', foreground='blue')  
        self.chat_log.tag_config('received', foreground='green')  

        self.bottom_frame = tk.Frame(self.root)
        self.bottom_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

        self.input_field = tk.Entry(self.bottom_frame, width=50)
        self.input_field.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.input_field.bind("<Return>", self.send_message)

        self.send_button = tk.Button(self.bottom_frame, text="ارسال", command=self.send_message, bg="#2196F3", fg="white")
        self.send_button.pack(side=tk.RIGHT, padx=5)

        self.close_button = tk.Button(self.bottom_frame, text="خروج", command=self.close, bg="#f44336", fg="white")
        self.close_button.pack(side=tk.RIGHT, padx=5)

     
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def start(self):
        self.username = simpledialog.askstring("نام کاربری", "لطفا نام کاربری خود را وارد کنید:")
        if not self.username:
            self.close()
            return

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.socket.connect((self.host, self.port))
            self.socket.send(self.username.encode('utf-8'))  
            self.add_message("به سرور متصل شدید.", 'system')
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()
            self.root.mainloop()
        except socket.error as e:
            self.add_message(f"خطا در اتصال: {e}", 'system')
            self.close()

    def send_message(self, event=None):
        message = self.input_field.get()
        self.input_field.delete(0, tk.END)
        if message:
            try:
                self.socket.send(f"{self.username}: {message}".encode('utf-8'))
                self.add_message(f"{self.username}: {message}", 'sent')  
            except socket.error as e:
                self.add_message(f"خطا در ارسال پیام: {e}", 'system')
                self.close()

    def receive_messages(self):
        while self.running:
            try:
                message = self.socket.recv(1024).decode('utf-8')
                self.add_message(message, 'received')
            except socket.error as e:
                self.add_message(f"ارتباط قطع شد: {e}", 'system')
                self.close()
                break
            except OSError:
                break

    def add_message(self, message, type='system'):
        self.chat_log.insert(tk.END, message + '\n', type)
        self.chat_log.see(tk.END)

    def close(self):
        self.running = False
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)  
                self.socket.close()
            except:
                pass
        if hasattr(self, 'root') and self.root:
            self.root.destroy()
        import os
        os._exit(0)


if __name__ == "__main__":
    client = ChatClient(HOST, PORT)
    client.start()
