"""
backend of senior capstone MatOS website
Authors:   Ixonblitz-MatOS
Version:   1.0
Date:      10/13/2023
Description: This is the backend of the MatOS website. It will handle all the requests from the frontend and send the appropriate responses. It will also handle the database and the login system. There may be possibly dynamic web change implementation.


Inner Workings:
    Functions:
        connect_to_host(HOST, PORT,msg)
            This function will connect to the host and send the message to the host. It will then receive a message from the host and print it out. It will then close the connection.

        send_http_request(url)
            This function will send a GET request to the URL and print out the response content.

        start_http_server(PORT)
            This function will start the http server at the specified port. It will then serve forever.

        error(severity, message)
            This function will use escape codes to create messages in different colors depending on severity and print the message in format:
                [severity] message
            severity:
                red=CRITICAL
                yellow=WARNING
                white=INFO

        askAdmin()
            This function will check in users.json if admin exists and ask for username/password and validate

        add_user(username, password,id)
            This function will add username and passwords and id to represent hierarchy where 1=admin and 0=user in their corresponding place in users.json

        remove_user(username)
            This function will remove user from users.json

        get_users()
            This function will get a list of all users separated by commas to be printed
            DOES NOT SEEK ACKNOWLEDGEMENT

        await_response()
            This function will wait for a response from the client for uuid acknowledgement
            true=succesful
            DOES NOT SEEK ACKNOWLEDGEMENT

        send_get_users(IP)
            This function will take get users string and send to the requestig client by IP
            DOES NOT SEEK ACKNOWLEDGEMENT
        handle_message(message)
            This function will take received messages and processes. 
            Following messages are:
                {"login" - {username: "username", password: "password","ip":"ip"}}
                {"logout" - {username: "username"}}
                {"get_users" - {username: "username"}}
                {"get_active_users" - {}}
                {"recv_special_id" - {}}
            users are managed in the file users.json

            return true if successful

        main()
            This is the testing function only
Packet Sending:
    1. Server receives login message from a host
    2. Server checks if user exists in users.json and verifies credentials
    3. Server sends a uuid to the host and notes the IP address associated with the uuid and account
    4. Server waits for a recv_special_id message from the host; if not received, the account and its uuid will be revoked
    5. Server receives a message from backend terminal(frontend backend.html)
    6. Server interprets it based on description in handle_message(message)
    :NOTE: Server will not send a message to the host unless it is a uuid or a get_users message
    :NOTE: Server will not send a message to the host unless it is a uuid or a get_active_users message
    :NOTE: Hosts work around the server work. Host code will adapt to this packet sending method MOST OF THE TIME.
"""
import socket
import requests
import http.server
import socketserver
import socket
import json
import uuid
import datetime
import getpass

#Constants
RECV_SPECIAL_ID="recv_special_id"

def connect_to_host(HOST, PORT,msg):
    # Create a socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Connect to the host
        s.connect((HOST, PORT))
        print(f"Connected to {HOST}:{PORT}")

        # Send a message to the host
        message = msg
        s.sendall(message.encode())
        print(f"Sent message: {message}")

        # Receive a message from the host
        data = s.recv(1024)
        print(f"Received message: {data.decode()}")

        # Close the connection
        s.close()
        print("Connection closed")

def send_http_request(url):
    # Send a GET request to the URL
    response = requests.get(url)

    # Print the response content
    print(response.content)
def start_http_server(PORT):
    #entry point
    
    Handler = http.server.SimpleHTTPRequestHandler
    
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print("serving at port", PORT)
        httpd.serve_forever()
class error:
    """
     class that uses escape codes to create messages in different colors depending on severity and print the message in format:
        [severity] message
    severity:
    red=CRITICAL
    yellow=WARNING
    white=INFO
    """
    def __init__(self):
        self.logs=[]
        self.colors={"red":"\033[91m","yellow":"\033[93m","white":"\033[97m"}
        self.severitylookup={"CRITICAL":"red","WARNING":"yellow","INFO":"white"}
        self.end="\033[0m"
        self.active_users=[]
    def print(self,severity,message):
        a=f"{self.colors[self.severitylookup[severity]]}[{severity}] {message}{self.end}"
        print(a)
        self.logs.append(a)
    def add_active_user(self,username,session_id,IP):self.active_users.append({"username":username,"session_id":session_id,"IP":IP})
global manager,server
manager=error()
server='127.0.0.1'
def askAdmin()->bool:
    """
    admin access=true
    check in users.json if admin exists and ask for username/password and validate
    
    """
    manager.print("INFO",f"Attempting Admin Access at {datetime.datetime.now()}")
    with open("users.json","r") as f:
        users=json.load(f)
        for user in users["users"]:
            if user["id"]==1:
                username=input("Username: ")
                password=getpass.getpass("Password: ")
                if user["username"]==username and user["password"]==password:
                    manager.print("INFO",f"Admin Access Granted at {datetime.datetime.now()} for user {username}")
                    return True
                else:
                    manager.print("WARNING",f"Admin Access Denied at {datetime.datetime.now()} for user {username}")
                    return False
def add_user(username, password,id):
    """
     Adds username and passwords and id to represent hierarchy where 1=admin and 0=user in their corresponding place in users.json
     
    """
    if id==1:
         manager.print("INFO",f"Attempting Adding user {username} at {datetime.datetime.now()} as an admin")
         if(askAdmin()):pass
         else:
              error("CRITICAL","Admin Attempt Failed")
    manager.print("INFO",f"Adding user {username} at {datetime.datetime.now()}")
    with open("users.json","r") as f:
            users=json.load(f)
            users["users"].append({"id":id,"name":username,"password":password})
    with open("users.json","w") as f:json.dump(users,f)
def remove_user(username):
    """
    removes user from users.json
    """
    manager.print("INFO",f"Attempting Removing user {username} at {datetime.datetime.now()}")
    if(askAdmin()):
        with open("users.json","r") as f:
            users=json.load(f)
            for user in users["users"]:
                if user["username"]==username:users["users"].remove(user)
        with open("users.json","w") as f:json.dump(users,f)
    else:error("CRITICAL","Admin Attempt Failed")
def get_users():
    """
    get a list of all users separated by commas to be printed
    """
    manager.print("INFO",f"Attempting Getting users at {datetime.datetime.now()}")
    if(askAdmin()):
        with open("users.json","r") as f:
            users=json.load(f)
            users_list=[]
            for user in users["users"]:users_list.append(user["username"])
            return ", ".join(users_list)
    else:error("CRITICAL","Admin Attempt Failed")
def await_response():
    """
    waits for a response from the client for uuid acknowledgement
    true=succesful
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((server,5151))
        s.listen()
        while True:
            conn, addr = s.accept()
            with conn:
                print('Connected by', addr)
                #check if addr is in active users IP
                for user in manager.active_users:
                    if user["IP"]==addr[0]:
                        
                        while True:
                            data = conn.recv(1024)
                            if not data: break
                            if data.decode()==RECV_SPECIAL_ID:return True
                            else:
                                #find active user with addr[0] IP then get the index of that user in active_users and remove it 
                                for user in manager.active_users:
                                    if user["IP"]==addr[0]:
                                        manager.active_users.remove(user)
                                        return False
                    return False
def send_get_users(IP):
    """
    take get users string and send to the requestig client by IP
    """
    with socket.socket(socket.Af_INET, socket.SOCK_STREAM) as s:
        s.bind((server,5151))
        s.connect((IP,5151))
        s.sendall(get_users().encode())
def get_active_users():
    """
    get a list of all active users separated by commas to be printed
    """
    manager.print("INFO",f"Getting active users at {datetime.datetime.now()} for send_get_active_users()")
    with open("users.json","r") as f:
            users=json.load(f)
            users_list=[]
            for user in manager.active_users:users_list.append(user["username"])
            return ", ".join(users_list)
def send_get_active_users(IP):
    """
    take get active users string and send to the requestig client by IP

    """

def handle_message(message):
    """
    takes received messages and processes. 
    Following messages are:
        {"login" - {username: "username", password: "password","ip":"ip"}}
        {"logout" - {username: "username"}}
        {"get_users" - {username: "username"}}
        {"get_active_users" - {}}
        {"recv_special_id" - {}}
    users are managed in the file users.json

    return true if successful
    """

    match message.keys()[0]:
        case "login":
                #get username and password from message format above
                username=message["login"]["username"]
                password=message["login"]["password"]
                #check if user exists in users.json
                with open("users.json","r") as f:
                    users=json.load(f)
                    for user in users["users"]:
                        if user["username"]==username:
                            #check if password is correct
                            if user["password"]==password:
                                #generate a session id and add to active users
                                session_id=str(uuid.uuid4())
                                manager.add_active_user(username,session_id,message["login"]["ip"])
                                #send session id to client
                                connect_to_host(message["login"]["ip"],5151,session_id)
                                #wait for recv_special_id message
                                #check if session id is correct
                                if await_response(RECV_SPECIAL_ID):
                                    manager.print("INFO",f"User {username} confirmed login at {datetime.datetime.now()}")
                                    return True
                                manager.print("CRITCAL",f"User {username} failed to confirm login at {datetime.datetime.now()}")
                                connect_to_host(message["login"]["ip"],5151,"NULL")
                                return False

                            else:
                                manager.print("WARNING",f"User {username} attempted login at {datetime.datetime.now()} with incorrect password")
                                connect_to_host(message["login"]["ip"],5151,"NULL")
                                return False
                        else:
                            manager.print("WARNING",f"User {username} attempted login at {datetime.datetime.now()} with incorrect username")
                            connect_to_host(message["login"]["ip"],5151,"NULL")
                            return False
        case "logout":
            #get username from message format above
            username=message["logout"]["username"]
            #check if user is in active users
            for user in manager.active_users:
                if user["username"]==username:
                    #remove user from active users
                    manager.active_users.remove(user)
                    manager.print("INFO",f"User {username} logged out at {datetime.datetime.now()}")
                    return True
            manager.print("WARNING",f"User {username} attempted logout at {datetime.datetime.now()} while not logged in")
            return False    
        case "get_users": 
            #if the username in the message has id=1 and active. elif (askAdmin()) else return False after logging  
            username=message["get_users"]["username"]
            for user in manager.active_users:
                if user["username"]==username:
                    if user["id"]==1:
                        manager.print("INFO",f"User {username} requested users at {datetime.datetime.now()}")
                        #get the username ip address from active users and pass to send_get_users()
                        for user in manager.active_users:
                            if user["username"]==username:
                                send_get_users(user["IP"])
                                return True
                    else:
                        manager.print("WARNING",f"User {username} attempted to get users at {datetime.datetime.now()} without admin privileges")
                        return False
        case "get_active_users":
            #if the username in the message has id=1 and active. elif (askAdmin()) else return False after logging  
            username=message["get_active_users"]["username"]
            for user in manager.active_users:
                if user["username"]==username:
                    if user["id"]==1:
                        manager.print("INFO",f"User {username} requested active users at {datetime.datetime.now()}")
                        #get the username ip address from active users and pass to send_get_users()
                        for user in manager.active_users:
                            if user["username"]==username:
                                send_get_active_users(user["IP"])
                                manager.print("INFO",f"Server sent User {username} active users at {datetime.datetime.now()}")
                                return True
                    else:
                        if(askAdmin()):
                            manager.print("INFO",f"User {username} requested active users at {datetime.datetime.now()}")
                            #get the username ip address from active users and pass to send_get_users()
                            for user in manager.active_users:
                                if user["username"]==username:
                                    send_get_active_users(user["IP"])
                                    manager.print("INFO",f"Server sent User {username} active users at {datetime.datetime.now()}")
                                    return True
                        manager.print("WARNING",f"User {username} attempted to get active users at {datetime.datetime.now()} without admin privileges")
                        return False             



def main():
    """
    testing function only
    FINISHED:
        ADD_USER()
        REMOVE_USER()
    
    """
    
if __name__ == "__main__":
    PORT=5151
    main()