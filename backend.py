"""
Author: Ixonblitz-MatOS
Date: 10/10/2021
Description:
    New Server backend using Websockets
    The original got screwed up on restart after saving. This is the second build
CONSTANTS:
    SERVER->str: Server IP
    PORT->int: Server Port
    VERSION->str: Server Version
    SETTINGS->dict: Server Settings
    NULL->str: Null value(used when false is returned or other issues arise)
FUNCTIONS:
    check_duplicate_users()->None
        checks in users.json if there are duplicate users and removes them leaving the first one
    askAdmin()->bool
        Asks for an admin password to complete a command and returns true if the admin is valid
    add_user(username:str, password:str,hierarchy:int)->bool
        Adds username and passwords and id to represent hierarchy where 1=admin and 0=user in their corresponding place in users.json
        TO ADD AN ADMIN askAdmin() must be true and will be called
        returns true if successful;else False
    remove_user(username:str)->bool
        removes user from users.json
        required Admin
        returns true if successful;else False
    get_all_users()->list
        requires admin access
        returns the list of users to send over websocket
        returns None if failed
CLASSES:
    error(NoDerive):
        holds active users
        returns get_active_users()->list
        returns logout_user(username:str)->None
        print(severity:str,message:str)->None

STORAGE NOTES:
    self.active_users->list: holds active users in format:
        [{"username":username,"session_id":session_id,"IP":IP,"recv":False},...]
    users=>users.json->dict: holds all users in format:
        {"users":[{"id":hierarchy,"username":username,"password":password},...]}

"""
from multiprocessing.pool import ThreadPool
from websockets.server import serve
from typing import NoReturn
import threading
import json
import uuid
import datetime
import getpass
import asyncio
#Constants

global manager,SERVER,NULL,VERSION,SETTINGS,PORT
PORT=5151
SERVER="192.168.20.175"
VERSION="0.0.2"
NULL="NULL"
SETTINGS={}
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
    def print(self,severity:str,message:str)->None:
        a=f"{self.colors[self.severitylookup[severity]]}[{severity}] {message}{self.end}"
        print(a)
        self.logs.append(a)
    def add_active_user(self,username:str,session_id:str,IP:str)->None:self.active_users.append({"username":username,"session_id":session_id,"IP":IP,"recv":False})
    def logout_user(self,username:str)->None:
        for i in self.active_users:
            if i["username"]==username:self.active_users.remove(i)
    def get_active_users(self)->list:return self.active_users
    def check_username_exists(self,username:str)->bool:
        """
        returns true if username in users.json
        """
        with open("users.json","r") as f:
            users=json.load(f)
            for user in users["users"]:
                if user["username"]==username:return True
            return False
    def get_users(self)->list:
        """
        returns all users in users.json with username only as a list
        """
        with open("users.json","r") as f:
            users=json.load(f)
            return [i["username"] for i in users["users"]]
    def validate_signin(self,username:str,password:str)->None:
        """
        checks username and password in users.json
        compares to parameters
        returns true if is correct
        false if not
        """
        with open("users.json","r") as f:
            users=json.load(f)
            for user in users["users"]:
                if user["username"]==username and user["password"]==password:return True
            return False
manager=error()
########################################################################################################################
#Server Functions
def check_duplicate_users():
    """
    checks in users.json if there are duplicate users and removes them leaving the first one
    """
    manager.print("INFO",f"Checking for duplicate users at {datetime.datetime.now()}")
    with open("users.json","r") as f:
        users=json.load(f)
        for user in users["users"]:
            for user2 in users["users"]:
                if user["username"]==user2["username"] and user["id"]==user2["id"] and user["password"]==user2["password"] and user!=user2:
                    manager.print("WARNING",f"Duplicate user {user['username']} found at {datetime.datetime.now()}")
                    users["users"].remove(user2)
    with open("users.json","w") as f:json.dump(users,f)
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
def add_user(username:str, password:str,hierarchy:int)->bool:
    """
     Adds username and passwords and id to represent hierarchy where 1=admin and 0=user in their corresponding place in users.json
     returns true if successful;else False
    """
    #check if user exists first in users.json without logging
    with open("users.json","r") as f:
        users=json.load(f)
        for user in users["users"]:
            if user["username"]==username:
                manager.print("WARNING",f"User {username} attempted to be added at {datetime.datetime.now()} but already exists")
                return False
    #If is adding an admin check for admin access
    if hierarchy==1:
         manager.print("INFO",f"Attempting Adding user {username} at {datetime.datetime.now()} as an admin")
         if(askAdmin()):pass
         else:
              error("CRITICAL","Admin Attempt Failed")
              return False  
    manager.print("INFO",f"Adding user {username} at {datetime.datetime.now()}")
    with open("users.json","r") as f:
            users=json.load(f)
            users["users"].append({"id":hierarchy,"username":username,"password":password})
    with open("users.json","w") as f:json.dump(users,f)
def remove_user(username:str)->bool:
    """
    remove user if admin is given
    """
    if askAdmin():
        manager.print("INFO",f"Attempting Removing user {username} at {datetime.datetime.now()}")
        with open("users.json","r") as f:
            users=json.load(f)
            for user in users["users"]:
                if user["username"]==username:
                    users["users"].remove(user)
        with open("users.json","w") as f:json.dump(users,f)
        manager.print("INFO",f"Removed user {username} at {datetime.datetime.now()}")
        return True
    else:
        manager.print("CRITICAL","Admin Attempt Failed")
        return False
def get_all_users()->list|None:
    """
    gets all users if admin is given
    returns none if failed
    """
    if askAdmin():return manager.get_users()
    else:
        manager.print("CRITICAL","Admin Attempt Failed")
        return None
def get_active_users()->list:return manager.get_active_users()
#reworking will finish last
def handle_message(message:str)->bool|dict:
    """
    takes received messages and processes. 
    Following messages are:
        {"login" - {username: "username", password: "password","ip":"ip"}}
        {"Active?" - {session_id: "session_id"}}
        {"logout" - {username: "username"}}
        {"get_users" - {username: "username"}}
        {"get_active_users" - {}}
        {"recv_special_id" - {username:username,session_id:session_id}}
    users are managed in the file users.json

    :returns bool: if command executed successfully without needing any additional sending
    :returns dict: made to be sent to client
    """
    message=json.loads(message)
    print(message)
    match list(message.keys())[0]:
        case "login":
            """
            Login Process:
                check if user exists in users.json and if password matches the username/password combo in users.json
                if user exists and password matches:
                    generate a session id and add to active users with an IP address and a recv flag for acknowledgement
                    return the dictionary to be sent out to the client

            :returns dict: send the uuid will be awaiting a recv_special_id message
            :returns bool: if the user does not exist or the password is incorrect or something else fails
            """
            username=message["login"]["username"]
            password=message["login"]["password"]
            if not message["login"]["ip"]:
                manager.print("WARNING",f"User {username} attempted login at {datetime.datetime.now()} with no ip address")
                return False
            if manager.check_username_exists(username):
                if manager.validate_signin(username=username,password=password):
                    session_id=uuid.uuid4()
                    manager.add_active_user(username,session_id,message["login"]["ip"])
                    manager.print("INFO",f"User {username} logged in at {datetime.datetime.now()} with session id {session_id}")
                    return {"recv_special_id":{"username":username,"session_id":session_id}}
                else:
                    manager.print("WARNING",f"User {username} attempted login at {datetime.datetime.now()} with incorrect password.")
                    return False
            else:
                manager.print("WARNING",f"User {username} attempted login at {datetime.datetime.now()} with incorrect username. ")
                return False
        case "recv_special_id":
            """
            Recv Special ID used for acknowledging login
            
            """
        case _:
            manager.print("WARNING",f"Unknown message received at {datetime.datetime.now()}")
            return False
########################################################################################################################
#Websocket Functions

#:TODO: Finish this
async def recvMessage(websocket):
        async for message in websocket:
            pool=ThreadPool(processes=1)
            res=pool.apply_async(handle_message,(message,))
            pool.close()
            await websocket.send(str(res.get()))
async def main():
    async with serve(recvMessage,SERVER,5151):await asyncio.Future()

#Touch Later
def listen()->NoReturn:
    """
    Listens on port 5151 on separate thread to listen for any http data sent using websocket and returns the content as a dictionary from its string form of "{command:{arguments:paramter,...}}"
    """
    manager.print("INFO",f"Running startup at {datetime.datetime.now()}")
    asyncio.run(main())
########################################################################################################################
def startup():
    """
    This startup function will be implemented later
    """
    threading.Timer(300,check_duplicate_users).start()#check for duplicates every 5 minutes
    listen()
if __name__=="__main__":
    manager.print("INFO",f"Server Started at {datetime.datetime.now()}")
    startup()
