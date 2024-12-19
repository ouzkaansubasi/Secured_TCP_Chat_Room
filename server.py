import socket
import ssl
from threading import Thread
import os

# Beyaz listeye alınmış IP adresleri
WHITE_LIST = ['127.0.0.1']

# Kara listeye alınmış IP adresleri
BLACK_LIST = []

def broadcast(msg, prefix=""):
    for client_socket in clients:
        client_socket.send(prefix.encode("utf-8") + msg)

def send_msgto_one_client(msg, client_name):
    for client_socket, name in clients.items():
        if name == client_name:
            client_socket.send(msg.encode("utf-8"))

def send_msgto_multiple_client(msg, members):
    if isinstance(members, list) != True:
        members = members.split(",")

    for name_client in members:
        for client_socket, name in clients.items():
            if name == name_client:
                client_socket.send(msg.encode("utf-8"))

def save_message(msg):
    with open("messages.txt", "a") as f:
        f.write(msg + "\n")

def get_past_messages():
    if not os.path.exists("messages.txt"):
        return []
    with open("messages.txt", "r") as f:
        messages = f.readlines()
    return messages

def accept_connections():
    while True:
        client_conn, client_address = server.accept()

        # IP filtreleme
        if client_address[0] in BLACK_LIST:
            print(f"Connection from {client_address[0]} blocked (blacklisted).")
            client_conn.close()
            continue
        if client_address[0] not in WHITE_LIST:
            print(f"Connection from {client_address[0]} blocked (not whitelisted).")
            client_conn.close()
            continue

        client_conn = context.wrap_socket(client_conn, server_side=True)  # SSL bağlantısı burada kuruluyor
        print("{0}:{1} has connected.".format(client_address[0], client_address[1]))

        client_conn.send("Isminizi yazin ve giris yapin:".encode("utf-8"))
        adresses[client_conn] = client_address
        Thread(target=handle_client, args=(client_conn,)).start()

def handle_client(client):
    name = client.recv(BUFFER_SIZE).decode("utf-8")
    clients[client] = name

    past_messages = get_past_messages()
    for msg in past_messages:
        client.send(msg.encode("utf-8"))

    hello_msg = "Merhaba {0}, Hosgeldiniz".format(name) + "+"
    tmp = " "
    tmp = tmp.join(list(clients.values()))

    hello_msg = hello_msg + tmp

    client.send(hello_msg.encode("utf-8"))

    join_msg = "{0} sohbet odasina katildi.".format(name) + "+"
    tmp = " "
    tmp = tmp.join(list(clients.values()))
    join_msg = join_msg + tmp
    broadcast(join_msg.encode("utf-8"))

    global opened_group_name, opened_group_members
    while True:
        client_msg = client.recv(BUFFER_SIZE)
        decoded_msg = client_msg.decode("utf-8")

        if decoded_msg == "cikis":
            client.send(bytes("{quit}", "utf-8"))
            client.close()

            del clients[client]
            broadcast(bytes("{0} sohbet odasindan ayrildi.".format(name), "utf-8"))
            break

        elif decoded_msg.find("shwmsg+") != -1:
            client_name = decoded_msg.split("+")[1]
            send_msgto_one_client("+shwmsg", client_name)

        elif decoded_msg.find("shwuserbymsg+") != -1:
            dest_client = decoded_msg.split("+")[1]
            selected_client_for_msg = decoded_msg.split("+")[2]

            if selected_client_for_msg in messages.keys():
                send_msgto_one_client("shwuserbymsg+" + messages[selected_client_for_msg] + "+" + selected_client_for_msg, dest_client)

        elif decoded_msg.find("opengroup+") != -1:
            dest_client = decoded_msg.split("+")[1]
            msg = "opengroup+"
            for i in clients.values():
                msg = msg + i + ","

            send_msgto_one_client(msg, dest_client)

        elif decoded_msg.find("groupopened+") != -1:
            group_name = decoded_msg.split("+")[1]
            opened_group_name = group_name

            opened_group_members = decoded_msg.split("+")[2]
            opened_group_members = opened_group_members.split(",")

        elif decoded_msg.find("$") != -1 and decoded_msg.split("+")[1] in opened_group_members:
            decoded_msg = decoded_msg.split("+")[0]
            decoded_msg = decoded_msg.replace("$", "")

            msg = "groupmessage+" + decoded_msg + "+" + opened_group_name + "+" + name
            send_msgto_multiple_client(msg, opened_group_members)

        elif decoded_msg.find("$") != -1 and decoded_msg.find("+") != -1:
            decoded_msg = decoded_msg.split("$")[1].split("+")[0]
            encoded_msg = decoded_msg.encode("utf-8")
            broadcast(encoded_msg, name + ": ")

        else:
            if name in messages.keys():
                messages[name] = messages[name] + "," + decoded_msg
            else:
                messages[name] = decoded_msg

            broadcast(client_msg, name + ": ")
            save_message(name + ": " + decoded_msg)  # Mesajı kaydet

clients = {}
adresses = {}

messages = {}

global opened_group_members, opened_group_name
opened_group_members = []
opened_group_name = " "

TCP_IP = "127.0.0.1"
TCP_PORT = 5005
BUFFER_SIZE = 1024

server = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0)
server.bind((TCP_IP, TCP_PORT))

context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.load_cert_chain(certfile="server.crt", keyfile="server.key")

if __name__ == "__main__":
    server.listen(5)
    print("Baglanti icin bekleniyor...")
    thread = Thread(target=accept_connections)
    thread.start()
    thread.join()
    server.close()