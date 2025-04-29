import socket
import time
import threading
import json
import tkinter as tk
import os
from tkinter import scrolledtext
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import secrets
import base64

class ChatAppClient:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat App")
        self.root.geometry("300x200")  # Initial smaller size
        self.root.minsize(300, 200)
        self.client = None
        self.stop_threads = False
        self.chat_windows = {}
        self.sessions = {}

        # GUI Setup
        self.connection_frame = None
        self.users_frame = None
        self.setup_connection_gui()

    def setup_connection_gui(self):
        # Create a frame for connection settings
        self.connection_frame = tk.Frame(self.root)
        self.connection_frame.pack(pady=10, fill=tk.BOTH, expand=True)

        # Wrapper frame for centering
        wrapper_frame = tk.Frame(self.connection_frame)
        wrapper_frame.pack(expand=True)

        # Username
        username_frame = tk.Frame(wrapper_frame)
        username_frame.pack(pady=5)
        self.label_username = tk.Label(username_frame, text="Username:", anchor="w", width=10)
        self.label_username.pack(side=tk.LEFT, padx=5)
        self.entry_username = tk.Entry(username_frame, width=20)
        self.entry_username.pack(side=tk.LEFT, padx=5)

        # IP Address
        ip_frame = tk.Frame(wrapper_frame)
        ip_frame.pack(pady=5)
        self.label_ip = tk.Label(ip_frame, text="IP address:", anchor="w", width=10)
        self.label_ip.pack(side=tk.LEFT, padx=5)
        self.entry_ip = tk.Entry(ip_frame, width=20)
        self.entry_ip.pack(side=tk.LEFT, padx=5)
        self.entry_ip.insert(0, "127.0.0.1")

        # Port
        port_frame = tk.Frame(wrapper_frame)
        port_frame.pack(pady=5)
        self.label_port = tk.Label(port_frame, text="Port:", anchor="w", width=10)
        self.label_port.pack(side=tk.LEFT, padx=5)
        self.entry_port = tk.Entry(port_frame, width=20)
        self.entry_port.pack(side=tk.LEFT, padx=5)
        self.entry_port.insert(0, "8000")

        # Connect Button
        self.btn_connect = tk.Button(wrapper_frame, text="Connect", command=self.connect)
        self.btn_connect.pack(pady=10)

    def setup_users_gui(self):
        # Adjust window size for user list
        self.root.geometry("250x400")
        self.root.minsize(250, 400)

        # Create a frame for the user list and refresh button
        self.users_frame = tk.Frame(self.root, height=10)
        self.users_frame.pack(pady=5, fill=tk.BOTH, expand=False)

        self.label_online = tk.Label(self.users_frame, text="Online Users")
        self.label_online.pack(side=tk.LEFT, padx=10)

        self.btn_refresh_users = tk.Button(self.users_frame, text="Refresh", command=self.GetUsersList)
        self.btn_refresh_users.pack(side=tk.RIGHT, padx=10)

        # Listbox for displaying users
        self.users_listbox = tk.Listbox(self.root, width=30, height=10)
        self.users_listbox.pack(pady=10, fill=tk.BOTH, expand=True)
        #Groups List
        self.groups_frame = tk.Frame(self.root, height=10)
        self.groups_frame.pack(pady=5, fill=tk.BOTH, expand=False)

        self.label_groups = tk.Label(self.groups_frame, text="Groups")
        self.label_groups.pack(side=tk.LEFT, padx=10)

        self.btn_add_groups = tk.Button(self.groups_frame, text="+", command=self.OpenCreateGroup)
        self.btn_add_groups.pack(side=tk.RIGHT, padx=10)

        self.btn_refresh_groups = tk.Button(self.groups_frame, text="Refresh", command=self.GetGroupsList)
        self.btn_refresh_groups.pack(side=tk.RIGHT, padx=10)

        # Listbox for displaying users
        self.groups_listbox = tk.Listbox(self.root, width=30, height=15)
        self.groups_listbox.pack(pady=10, fill=tk.BOTH, expand=True)

        # Force GUI refresh
        self.root.update_idletasks()

        self.users_listbox.bind("<Double-1>", self.StartChatUser)
        self.groups_listbox.bind("<Double-1>", self.StartChatGroup)
    def generate_rsa_keys(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def encrypt_public_key(self,public_key, data):
        ciphertext = public_key.encrypt(
            data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext
    
    def decrypt_private_key(self,private_key, ciphertext):
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return plaintext
    def encrypt_private_key(self, private_key, data):
        ciphertext = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return ciphertext
    
    def decrypt_public_key(self, public_key, data, signature):
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception as e:
            return False
    
    def generate_aes_key(self):
        password = secrets.token_bytes(32)
        salt = secrets.token_bytes(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password)

    def encrypt_message(self,aes_key, plaintext):
        nonce = secrets.token_bytes(12)
        encryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce),
            backend=default_backend()
        ).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce + encryptor.tag + ciphertext

    def decrypt_message(self,aes_key, encrypted_message):
        nonce = encrypted_message[:12]
        tag = encrypted_message[12:28]
        ciphertext = encrypted_message[28:]
        decryptor = Cipher(
            algorithms.AES(aes_key),
            modes.GCM(nonce, tag),
            backend=default_backend()
        ).decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        return plaintext
    def connect(self):
        self.private_key, self.public_key=self.generate_rsa_keys()
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        self.username = self.entry_username.get()
        ip = self.entry_ip.get()
        port = int(self.entry_port.get())
        self.root.title(f"Chat App:{self.username}")
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client.connect((ip, port))
        self.client.send(self.public_key_pem)
        self.aes_key=self.decrypt_private_key(self.private_key,self.client.recv(256))
        self.client.send(self.encrypt_message(self.aes_key,self.username.encode('utf-8')))
        self.message_handler = threading.Thread(target=self.HandleMessage)
        self.message_handler.start()
        time.sleep(0.1)
        
        # Transition to user list GUI
        self.connection_frame.destroy()
        self.setup_users_gui()
        time.sleep(0.1)
        self.GetUsersList()
        time.sleep(0.1)
        self.GetGroupsList()


    def HandleMessage(self):
        while True:
            packet = json.loads(self.decrypt_message(self.aes_key,self.client.recv(4096)).decode('utf-8'))
            if packet["type"] == "UsersList":
                self.DrawUsersList(packet["data"])
            elif packet["type"] == "GroupsList":
                self.DrawGroupsList(packet["data"])
            elif packet["type"] == "UserMessage":
                sender = packet["user"]
                text = self.decrypt_message(self.sessions[sender]["sessionkey"],base64.b64decode(packet["message"].encode('utf-8'))).decode('utf-8')
                digsign=base64.b64decode(packet["digsign"].encode('utf-8'))
                if self.decrypt_public_key(self.sessions[sender]["publickey"],text.encode('utf-8'),digsign):
                    self.display_user_message(sender, text)
            elif packet["type"] == "GroupMessage":
                group = packet["group"]
                sender = packet["user"]
                text = self.decrypt_message(self.sessions[group]["sessionkey"],base64.b64decode(packet["message"].encode('utf-8'))).decode('utf-8')
                digsign=base64.b64decode(packet["digsign"].encode('utf-8'))
                if self.decrypt_public_key(self.sessions[group]["publickeys"][sender],text.encode('utf-8'),digsign):
                    self.display_group_message(group, sender, text)
            elif packet["type"] == "UserFile":
                sender = packet["user"]
                text = packet["filename"]
                signature=base64.b64decode(packet["digsign"].encode('utf-8'))
                file_data = b""
                bytes_received = 0
                while bytes_received < packet["filesize"]:
                    data = self.decrypt_message(self.sessions[sender]["sessionkey"],self.decrypt_message(self.aes_key,self.client.recv(1024)))
                    if not data:
                        break
                    file_data += data
                    bytes_received += len(data)
                if self.decrypt_public_key(self.sessions[sender]["publickey"], file_data, signature):
                    self.display_user_message(sender, text)
                    with open(packet["filename"], 'wb') as f:
                        f.write(file_data)
            elif packet["type"] == "GroupFile":
                sender = packet["user"]
                group = packet["group"]
                text = packet["filename"]
                signature=base64.b64decode(packet["digsign"].encode('utf-8'))
                file_data = b""
                bytes_received = 0
                while bytes_received < packet["filesize"]:
                    data = self.decrypt_message(self.sessions[group]["sessionkey"],self.decrypt_message(self.aes_key,self.client.recv(1024)))
                    if not data:
                        break
                    file_data += data
                    bytes_received += len(data)
                if self.decrypt_public_key(self.sessions[group]["publickeys"][sender], file_data, signature):
                    self.display_group_message(group, sender, text)
                    with open(self.username+packet["filename"], 'wb') as f:
                        f.write(file_data)
            elif packet["type"] == "UserPublicKey":
                public_key_pem=base64.b64decode(packet['publickey'].encode('utf-8'))
                public_key=serialization.load_pem_public_key(public_key_pem)
                self.CreateUserSession(packet["user"],public_key)
            elif packet["type"] == "SessionKeyExchange":
                self.sessions[packet["user"]]={
                    "publickey":serialization.load_pem_public_key(base64.b64decode(packet["publickey"].encode('utf-8'))),
                    "sessionkey":self.decrypt_private_key(self.private_key,base64.b64decode(packet["sessionkey"].encode('utf-8')))
                }
            elif packet["type"] == "GroupPublicKeys":
                public_keys_pems={}
                public_keys={}
                for _ in list(packet["publickeys"].keys()):
                    public_keys_pems[_]=packet["publickeys"][_]
                    public_keys[_]=serialization.load_pem_public_key(base64.b64decode(packet["publickeys"][_].encode('utf-8')))
                public_keys_pems[self.username]=base64.b64encode(self.public_key_pem).decode('utf-8')
                session_key=self.generate_aes_key()
                for _ in list(packet["publickeys"].keys()):
                    data={
                        "type":"GroupSessionKeyExchange",
                        "user":_,
                        "group":packet["group"],
                        "sessionkey":base64.b64encode(self.encrypt_public_key(public_keys[_],session_key)).decode('utf-8'),
                        "publickeyspems":public_keys_pems
                    }
                    self.client.send(self.encrypt_message(self.aes_key,json.dumps(data).encode('utf-8')))
                    time.sleep(0.1)

                self.sessions[packet["group"]]={
                    "sessionkey":session_key,
                    "publickeys":public_keys
                }
            elif packet["type"]=="GroupSessionKeyExchange":
                session_key=self.decrypt_private_key(self.private_key,base64.b64decode(packet["sessionkey"].encode('utf-8')))
                public_keys={}
                for _ in list(packet["publickeyspems"].keys()):
                    public_keys[_]=serialization.load_pem_public_key(base64.b64decode(packet["publickeyspems"][_].encode('utf-8')))
                self.sessions[packet["group"]]={
                    "sessionkey":session_key,
                    "publickeys":public_keys
                }

    def GetUsersList(self):
        UserGet = {"type": "GetUsersList"}
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(UserGet).encode('utf-8')))
        time.sleep(0.1)
    def GetGroupsList(self):
        GroupGet = {"type": "GetGroupsList"}
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(GroupGet).encode('utf-8')))
        time.sleep(0.1)
    def DrawUsersList(self, UsersList):
        def update_listbox():
            self.users_listbox.delete(0, tk.END)
            for user in UsersList:
                self.users_listbox.insert("end", user)
        self.root.after(0, update_listbox)
    def DrawGroupsList(self, GroupsList):
        def update_listbox():
            self.groups_listbox.delete(0, tk.END)
            for group in GroupsList:
                self.groups_listbox.insert("end", group)
        self.root.after(0, update_listbox)

    def StartChatUser(self, event=None):
        selection = self.users_listbox.curselection()
        if selection:
            user = self.users_listbox.get(selection[0])
            self.open_chat_window(user,'u')
    def StartChatGroup(self, event=None):
        selection = self.groups_listbox.curselection()
        if selection:
            group = self.groups_listbox.get(selection[0])
            self.open_chat_window(group,'g')

    def send_message_user(self, recipient, message):
        msg = {
            "type": "UserMessage",
            "user": recipient,
            "message":base64.b64encode(self.encrypt_message(self.sessions[recipient]["sessionkey"],message.encode('utf-8'))).decode('utf-8'),
            "digsign":base64.b64encode(self.encrypt_private_key(self.private_key,message.encode('utf-8'))).decode('utf-8')
        }
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(msg).encode('utf-8')))
    def send_file(self, recipient, filepath):
        with open(filepath, 'rb') as f:
            data = f.read()
        signature = self.encrypt_private_key(self.private_key, data)
        msg = {
            "type": "UserFile",
            "user": recipient,
            "filename": os.path.basename(filepath),
            "filesize":os.path.getsize(filepath),
            "digsign":base64.b64encode(signature).decode('utf-8')
        }
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(msg).encode('utf-8')))
        time.sleep(0.2)
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(968)
                if not data:
                    break
                self.client.send(self.encrypt_message(self.aes_key,self.encrypt_message(self.sessions[recipient]["sessionkey"],data)))

    def send_group_file(self, recipient, filepath):
        with open(filepath, 'rb') as f:
            data = f.read()
        signature = self.encrypt_private_key(self.private_key, data)
        msg = {
            "type": "GroupFile",
            "group": recipient,
            "filename": os.path.basename(filepath),
            "filesize":os.path.getsize(filepath),
            "digsign":base64.b64encode(signature).decode('utf-8')
        }
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(msg).encode('utf-8')))
        time.sleep(0.2)
        with open(filepath, 'rb') as f:
            while True:
                data = f.read(968)
                if not data:
                    break
                self.client.send(self.encrypt_message(self.aes_key,self.encrypt_message(self.sessions[recipient]["sessionkey"],data)))

    def send_message_group(self, recipient, message):
        msg = {
            "type": "GroupMessage",
            "group": recipient,
            "message": base64.b64encode(self.encrypt_message(self.sessions[recipient]["sessionkey"],message.encode('utf-8'))).decode('utf-8'),
            "digsign":base64.b64encode(self.encrypt_private_key(self.private_key,message.encode('utf-8'))).decode('utf-8')
        }
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(msg).encode('utf-8')))

    def open_chat_window(self, name, type):
        if name in self.chat_windows:
            try:
                if not self.chat_windows[name].window.winfo_exists():
                    del self.chat_windows[name]
            except Exception:
                del self.chat_windows[name]
        if name not in self.chat_windows:
            if type=='u':
                new_window = ChatWindowUser(self, name)
            elif type=='g':
                new_window = ChatWindowGroup(self, name)
            self.chat_windows[name] = new_window

    def display_user_message(self, sender, message):
        if sender not in self.chat_windows:
            self.open_chat_window(sender,'u')
        chat_window = self.chat_windows[sender]
        chat_window.display_message(f"{sender}: {message}")
    def display_group_message(self,group, sender, message):
        if group not in self.chat_windows:
            self.open_chat_window(group,'g')
        chat_window = self.chat_windows[group]
        chat_window.display_message(f"{sender}: {message}")
    def OpenCreateGroup(self):
        GroupAddWindow(self)
    def CreateGroup(self,groupname,userlist):
        pck={
            "type":"AddGroup",
            "group":groupname,
            "list":userlist
        }
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(pck).encode('utf-8')))
    def GetPublicKey(self,user):
        KeyGet={
            "type":"GetPublicKey",
            "user":user
        }
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(KeyGet).encode('utf-8')))
    def CreateUserSession(self,user,public_key):
        session_key=self.generate_aes_key()
        self.sessions[user]={
            "sessionkey":session_key,
            "publickey":public_key
        }
        data={
            "type":"SessionKeyExchange",
            "user":user,
            "publickey":base64.b64encode(self.public_key_pem).decode('utf-8'),
            "sessionkey":base64.b64encode(self.encrypt_public_key(public_key,session_key)).decode('utf-8')
        }
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(data).encode('utf-8')))
    def GetGroupPublicKeys(self,group):
        KeyGet={
            "type":"GetPublicKey",
            "group":group
        }
        self.client.send(self.encrypt_message(self.aes_key,json.dumps(KeyGet).encode('utf-8')))

class ChatWindowUser:
    def __init__(self, client, user):
        self.client = client
        self.user = user
        if user not in self.client.sessions:
            self.client.GetPublicKey(user)
        self.window = tk.Toplevel()
        self.window.title(f"Chat with {user}")
        self.window.geometry("400x300")
        self.window.minsize(400, 300)

        # Chat history
        self.history = scrolledtext.ScrolledText(self.window, state="disabled", width=50, height=15)
        self.history.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Message entry
        self.entry = tk.Entry(self.window, width=50)
        self.entry.pack(padx=10, pady=5, fill=tk.X)
        self.entry.bind("<Return>", self.send_message)

        # Button frame
        frame_buttons = tk.Frame(self.window)
        frame_buttons.pack(pady=5, fill=tk.X)

        # Send Button
        self.btn_send = tk.Button(frame_buttons, text="Send", command=self.send_message)
        self.btn_send.pack(side=tk.LEFT, padx=5)
        #File Button
        self.btn_file = tk.Button(frame_buttons, text="Send File", command=self.send_file)
        self.btn_file.pack(side=tk.LEFT, padx=5)
        # Exit Button
        self.btn_exit = tk.Button(frame_buttons, text="Exit", command=self.on_close)
        self.btn_exit.pack(side=tk.RIGHT, padx=5)

    def display_message(self, message):
        self.history.config(state="normal")
        self.history.insert("end", message + "\n")
        self.history.config(state="disabled")
        self.history.see("end")

    def send_message(self, event=None):
        message = self.entry.get()
        if message:
            self.client.send_message_user(self.user, message)
            self.display_message(f"You: {message}")
            self.entry.delete(0, "end")
    def send_file(self):
        filepath = filedialog.askopenfilename(title="Wybierz plik", filetypes=(("Wszystkie pliki", "*.*"),))
        if filepath:
            self.display_message(f"You sent {os.path.basename(filepath)}")
            self.client.send_file(self.user, filepath)
    def on_close(self):
        if self.user in self.client.chat_windows:
            del self.client.chat_windows[self.user]
        self.window.destroy()

class ChatWindowGroup:
    def __init__(self, client, group):
        self.client = client
        self.group = group
        self.window = tk.Toplevel()
        self.window.title(f"Chat with {group}")
        self.window.geometry("400x300")
        self.window.minsize(400, 300)

        # Chat history
        self.history = scrolledtext.ScrolledText(self.window, state="disabled", width=50, height=15)
        self.history.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Message entry
        self.entry = tk.Entry(self.window, width=50)
        self.entry.pack(padx=10, pady=5, fill=tk.X)
        self.entry.bind("<Return>", self.send_message)

        # Button frame
        frame_buttons = tk.Frame(self.window)
        frame_buttons.pack(pady=5, fill=tk.X)

        # Send Button
        self.btn_send = tk.Button(frame_buttons, text="Send", command=self.send_message)
        self.btn_send.pack(side=tk.LEFT, padx=5)

        #File Button
        self.btn_file = tk.Button(frame_buttons, text="Send File", command=self.send_file)
        self.btn_file.pack(side=tk.LEFT, padx=5)

        # Exit Button
        self.btn_exit = tk.Button(frame_buttons, text="Exit", command=self.on_close)
        self.btn_exit.pack(side=tk.RIGHT, padx=5)

    def display_message(self, message):
        self.history.config(state="normal")
        self.history.insert("end", message + "\n")
        self.history.config(state="disabled")
        self.history.see("end")
    
    def send_file(self):
        filepath = filedialog.askopenfilename(title="Wybierz plik", filetypes=(("Wszystkie pliki", "*.*"),))
        if filepath:
            self.display_message(f"You sent {os.path.basename(filepath)}")
            self.client.send_group_file(self.group, filepath)

    def send_message(self, event=None):
        message = self.entry.get()
        if message:
            self.client.send_message_group(self.group, message)
            self.display_message(f"You: {message}")
            self.entry.delete(0, "end")

    def on_close(self):
        if self.group in self.client.chat_windows:
            del self.client.chat_windows[self.group]
        self.window.destroy()
class GroupAddWindow:
    def __init__(self, client):
        self.client = client
        self.window = tk.Toplevel()
        self.window.geometry("350x150")
        self.window.minsize(350, 150)
        self.window.title("Add Group")
        #GUI
        self.wrapper_frame = tk.Frame(self.window)
        self.wrapper_frame.pack(expand=True)
        self.group_frame = tk.Frame(self.wrapper_frame)
        self.group_frame.pack(pady=5)
        self.label_groupname = tk.Label(self.group_frame, text="Group name:", anchor="w", width=10)
        self.label_groupname.pack(side=tk.LEFT, padx=5)
        self.entry_groupname = tk.Entry(self.group_frame, width=20)
        self.entry_groupname.pack(side=tk.LEFT, padx=5)
        self.checkbox_frame = tk.Frame(self.wrapper_frame)
        self.checkbox_frame.pack()
        self.check_vars = []
        self.items = self.client.users_listbox.get(0, 'end')
        for item in self.items:
            var = tk.BooleanVar()
            checkbox = tk.Checkbutton(self.checkbox_frame, text=item, variable=var)
            checkbox.pack(side=tk.LEFT, padx=5, anchor=tk.W)
            self.check_vars.append((item, var))
        self.submit_button = tk.Button(self.wrapper_frame, text="Submit", command=self.collect_checked)
        self.submit_button.pack()
    def collect_checked(self):
        selected_items = [item for item, var in self.check_vars if var.get()]
        self.client.CreateGroup(self.entry_groupname.get(),selected_items)
        time.sleep(0.1)
        self.client.GetGroupPublicKeys(self.entry_groupname.get())
        self.window.destroy()
if __name__ == "__main__":
    root = tk.Tk()
    app = ChatAppClient(root)
    root.mainloop()
