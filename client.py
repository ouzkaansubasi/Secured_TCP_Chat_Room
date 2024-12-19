import socket
import ssl
from threading import Thread
import tkinter as tk
from tkinter import ttk
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
from Crypto.Random import get_random_bytes

# Generate a random 16-byte (128-bit) key for AES-128
SECRET_KEY = get_random_bytes(16)

global client_name, first_time, message_records

client_name = " "
first_time = True
message_records = []

def encrypt_message(message):
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(message.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return iv + ct

def decrypt_message(encrypted_message):
    iv = base64.b64decode(encrypted_message[:24])
    ct = base64.b64decode(encrypted_message[24:])
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')

def receive_msg():
    while True:
        try:
            msg = client_socket.recv(BUFFER_SIZE).decode("utf-8")
            global client_name

            if msg == "+shwmsg":
                top = tk.Tk()
                msg_history = tk.Listbox(top, bg="#00FFCA", height=15, width=50, font=("Courier", 12, "bold"))
                for i, jmsg in enumerate(message_records):
                    if i > 0:
                        msg_history.insert(tk.END, jmsg)
                msg_history.pack()
                btnexit = tk.Button(top, text="Tamam", command=top.destroy)
                top.mainloop()

            elif msg.find("Hosgeldiniz") != -1:
                msg_to_print = msg.split("+")[0]
                online_users = msg.split("+")[1]

                users_listbox.insert(tk.END, "Online Kullanicilar:")
                for user in online_users.split(" "):
                    users_listbox.insert(tk.END, user)

                msg_list.insert(tk.END, msg_to_print)
            elif msg.find("sohbet odasina katildi.") != -1:
                msg_to_print = msg.split("+")[0]
                online_users = msg.split("+")[1]
                users_listbox.delete(0, tk.END)

                users_listbox.insert(tk.END, "Online Kullanicilar:")
                for user in online_users.split(" "):
                    users_listbox.insert(tk.END, user)

                msg_list.insert(tk.END, msg_to_print)

            elif msg.find("shwuserbymsg+") != -1:
                msgs = msg.split("+")[1].split(",")
                selected_client = msg.split("+")[2]

                top = tk.Tk()
                lbox = tk.Listbox(top, bg="white", height=15, width=50)
                for i in msgs:
                    i = selected_client + ": " + i
                    lbox.insert(tk.END, i)

                button = tk.Button(top, text="Tamam", command=top.destroy)
                lbox.pack()
                button.pack()
                top.mainloop()

            else:
                message_records.append(msg)
                if msg != "Isminizi yazin ve giris yapin:":
                    encrypted_msg = encrypt_message(msg)
                    with open("messages.txt", "a") as output:
                        output.write(encrypted_msg + '\n')

                if msg != "+shwmsg":
                    msg_list.insert(tk.END, msg)

        except OSError:
            pass

def search_message():
    def callback():
        global message_records
        lbox.delete(0, tk.END)
        keyword = entry.get()

        for i, msg in enumerate(message_records):
            if i == 0:
                continue
            if msg.split(":")[1].find(keyword) != -1:
                lbox.insert(tk.END, msg)

    def exit():
        lbox.delete(0, tk.END)
        top.destroy()

    top = tk.Tk()
    lbox = tk.Listbox(top, height=15, width=50, bg="white")
    entry = tk.Entry(top, bg="white")
    search_btn = tk.Button(top, text="Ara", command=callback)
    button = tk.Button(top, text="Cikis", command=exit)
    lbox.pack()
    entry.pack()
    search_btn.pack()
    button.pack()
    top.mainloop()

def send_msg(event=None):
    global first_time, client_name
    if first_time == True:
        msg = my_msg.get()
        client_name = msg
        root.title(client_name)
        first_time = False

    msg = my_msg.get()

    if msg != "" or msg != " ":
        my_msg.set("")

        if msg.find("$") != -1:
            msg = msg + "+" + client_name
            client_socket.send(msg.encode("utf-8"))

        elif msg == "{quit}":
            client_socket.close()
            root.quit()
        else:
            client_socket.send(msg.encode("utf-8"))

def show_msg_records():
    global client_name
    cmsg = "shwmsg+" + client_name
    client_socket.send(cmsg.encode("utf-8"))

def show_user_msg():
    global client_name
    def callback():
        selected_client = combobox.get()
        top.destroy()
        cmsg = "shwuserbymsg+" + client_name + "+" + selected_client
        client_socket.send(cmsg.encode("utf-8"))

    top = tk.Tk()
    label = tk.Label(top, text="Kullanici Sec:")
    val = list(users_listbox.get(0, tk.END))
    val.remove("Online Kullanicilar:")
    combobox = ttk.Combobox(top, values=val)

    btn = tk.Button(top, text="Tamam", command=callback)
    label.grid(row=0, column=0)
    combobox.grid(row=0, column=1)
    btn.grid(row=1, column=0)
    top.mainloop()

def on_closing(event=None):
    my_msg.set("{quit}")

WIDTH = 1200
HEIGHT = 400

root = tk.Tk()
root.title("Sohbet Odasi")

canvas = tk.Canvas(root, width=WIDTH, height=HEIGHT)
canvas.pack()

user_frame = tk.Frame(canvas, bg="#0A4D68")
user_frame.place(relx=0, rely=0, relwidth=0.60, relheight=1)

result_frame = tk.Frame(canvas, bd=5, bg="white")
result_frame.place(relx=0.60, y=0, relwidth=0.40, relheight=1)

users_listbox = tk.Listbox(result_frame, bg="#00FFCA", font=("Courier", 12, "bold"))
users_listbox.place(relx=0, rely=0, relheight=1, relwidth=1)

msg_frame = tk.Frame(user_frame, bd=5, bg="#0A4D68")
msg_frame.place(relx=0, rely=0, relheight=0.80, relwidth=1)

button_frame = tk.Frame(user_frame, bd=5, bg="#0A4D68")
button_frame.place(relx=0, rely=0.80, relheight=0.20, relwidth=1)

my_msg = tk.StringVar()
my_msg.set("Buraya Yaziniz...")

scrollbar = tk.Scrollbar(msg_frame)
msg_list = tk.Listbox(msg_frame, height=15, width=80, yscrollcommand=scrollbar.set, font=("Courier", 12, "bold"))

scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
msg_list.pack(side=tk.LEFT, fill=tk.BOTH)

entry_field = tk.Entry(button_frame, textvariable=my_msg, font=("Courier", 12, "bold"), bg="#05BFDB")
entry_field.bind("<Return>", send_msg)
entry_field.place(relx=0, rely=0, relheight=0.5, relwidth=1)

send_button = tk.Button(button_frame, text="Gonder", command=send_msg, bg="#00FFCA", font=("Helvetica", 10, "bold"))
send_button.place(relx=0, rely=0.5, relheight=0.5, relwidth=0.10)

show_msg_by_user = tk.Button(button_frame, text="Kullanicinin Mesajlari", command=show_user_msg, bg="#00FFCA", font=("Helvetica", 10, "bold"))
show_msg_by_user.place(relx=0.10, rely=0.5, relheight=0.5, relwidth=0.30)

show_past_msg = tk.Button(button_frame, text="Mesaj Kayitlari", command=show_msg_records, bg="#00FFCA", font=("Helvetica", 10, "bold"))
show_past_msg.place(relx=0.40, rely=0.5, relheight=0.5, relwidth=0.30)

find_keyword_btn = tk.Button(button_frame, text="Mesaj Ara", command=search_message, bg="#00FFCA", font=("Helvetica", 10, "bold"))
find_keyword_btn.place(relx=0.70, rely=0.5, relheight=0.5, relwidth=0.30)

root.protocol("WM_DELETE_WINDOW", on_closing)

BUFFER_SIZE = 1024
TCP_IP = "127.0.0.1"
TCP_PORT = 5005
SERVER_ADD = (TCP_IP, TCP_PORT)

client_socket = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)

context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
context.load_verify_locations(cafile="server.crt")  

client_socket = context.wrap_socket(client_socket, server_hostname="127.0.0.1")

client_socket.connect(SERVER_ADD)

receive_thread = Thread(target=receive_msg)
receive_thread.start()

root.mainloop()
