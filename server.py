# Noam Chen

# IMPORTS
import socket  # Importing socket module for network communication
import threading  # Importing threading module for handling multiple clients concurrently
import sqlite3  # Importing sqlite3 module for database management
# ==================================================

HOST = "IP ADDRESS"
PORT = 8080  # SAME PORT IN CLIENT AND THE SERVER

# SERVER CLASS
class Server:
    def __init__(self, host, port):
        self.HOST = host  # Assigning host IP
        self.PORT = port  # Assigning port number

    # Function to handle individual client connections
    def handle_client(self, client_socket, client_address):
        try:
            while True:
                # Receive data from the client
                data = client_socket.recv(1024).decode()
                command = data.split("/:")[0]  # Extracting command from received data
                print(f"Received from {client_socket.getpeername()}: {data}")  # Printing received data
                
                # LOGIN COMMAND
                if command == "Login":
                    command, username, password = data.split("/:")  # Extracting username and password
                    # Connecting to database and checking credentials
                    conn = sqlite3.connect("project.db")
                    cursor = conn.cursor()
                    db = cursor.execute("SELECT username, password From users WHERE username = ?", (username,))
                    if db.fetchone():
                        db = cursor.execute("SELECT username, password FROM users WHERE username = ?", (username,))
                        username_db, password_db = db.fetchone()
                        # Validating username and password
                        if username == username_db and password == password_db:
                            conn.commit()
                            conn.close()
                            client_socket.send("Login successful".encode())
                        else:
                            conn.commit()
                            conn.close()
                            client_socket.send("Login failed".encode())
                    else:
                        conn.commit()
                        conn.close()
                        client_socket.send("Username does not exist".encode())

                # SIGNUP COMMAND
                elif command == "Signup":
                    command, username, password = data.split("/:")
                    # Connecting to database and checking if username is already taken
                    conn = sqlite3.connect("project.db")
                    cursor = conn.cursor()
                    taken = cursor.execute("SELECT username, password FROM users WHERE username=?", (username,))
                    if taken.fetchone() is None:
                        # Inserting new user into the database
                        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
                        conn.commit()
                        conn.close()
                        client_socket.send("Signup successful".encode())
                    else:
                        conn.commit()
                        conn.close()
                        client_socket.send("Username taken".encode())

                # ADD COMMAND
                elif command == "Add":
                    command, username, header, date, content = data.split("/:")
                    # Connecting to database and adding new task
                    conn = sqlite3.connect("project.db")
                    cursor = conn.cursor()
                    # check if there is task with the same name
                    taken = cursor.execute("SELECT task FROM tasks WHERE task=? AND username=?", (header, username))
                    if taken.fetchone() is None:
                        # insert into the database the given task
                        cursor.execute("INSERT INTO tasks (username, task, date, content) VALUES (?, ?, ?, ?)", (username, header, date, content))
                        conn.commit()
                        conn.close()
                        client_socket.send("Task added".encode())
                    else:
                        conn.commit()
                        conn.close()
                        client_socket.send("The name for the task has been taken".encode())  

                # DELETE COMMAND
                elif command == "Delete":
                    command, username, header, date = data.split("/:")
                    # Connecting to database and deleting task
                    conn = sqlite3.connect("project.db")  
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM tasks WHERE username=? AND task=? AND date=?", (username, header, date))
                    conn.commit()
                    conn.close()
                    client_socket.send("Task deleted".encode())

                # SEND THE CONTENT OF THE NOTE
                elif command == "View":
                    command, username, header, date = data.split("/:")
                    # Connecting to database and retrieving task content
                    conn = sqlite3.connect("project.db") 
                    cursor = conn.cursor()
                    content = cursor.execute("SELECT content FROM tasks WHERE task=? AND username=?", (header, username))
                    content = content.fetchone()
                    content = content[0]
                    conn.commit()
                    conn.close()
                    client_socket.send(content.encode())
                
                # EDIT THE NOTE
                elif command == "Edit":
                    command, username, header, content, date = data.split("/:")
                    # Connecting to database and updating task content
                    conn = sqlite3.connect("project.db")
                    cursor = conn.cursor()
                    cursor.execute("UPDATE tasks SET content=?, date=? WHERE username=? AND task=?", (content, date, username, header))
                    conn.commit()
                    conn.close()
                    client_socket.send("Success".encode())

                # CLOSE THE CONNECTION
                elif command == "Quit":
                    break

                # LOADING ALL THE TASKS
                else:
                    # Connecting to database and loading all tasks for a user
                    conn = sqlite3.connect("project.db")  
                    cursor = conn.cursor()
                    tasks = cursor.execute("SELECT task, date FROM tasks WHERE username=?", (command,))

                    if tasks.fetchall():
                        tasks = cursor.execute("SELECT task, date FROM tasks WHERE username=?", (command,))
                        tasks = tasks.fetchall()
                        # combine all the tasks and send to client
                        combined_tasks = [item1 + " " + item2 for item1, item2 in tasks]
                        message = "/:".join(combined_tasks)

                        conn.commit()
                        conn.close()

                        client_socket.send(message.encode())
                    else:
                        client_socket.send("None".encode())

        except ConnectionResetError:
            print(f"Connection with {client_address} reset by client.")

        # Close the connection with the client
        finally:
            client_socket.close()
            print(f"Connection with {client_address} closed.")

    # Function to start the server
    def start_server(self):
        server_address = (self.HOST, self.PORT)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(server_address)
        server_socket.listen(5)
        print(f"Server listening on {server_address[0]}:{server_address[1]}")
        
        # Connecting / Creating the data base (project.db)
        conn = sqlite3.connect("project.db")
        cursor = conn.cursor()

        # Creating the table "users"
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
        """)

        # Creating the table "tasks"
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                task TEXT NOT NULL,
                content TEXT NOT NULL,
                date TEXT NOT NULL
            )
        """)
        
        # Saves the table and disconnect from the database
        conn.commit()
        conn.close()
        
        while True:
            # use threads to be able to connect multiple clients
            client_socket, client_address = server_socket.accept()
            print(f"Connection from {client_address[0]}:{client_address[1]}")
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_thread.start()

# START
if __name__ == "__main__":
    server = Server(HOST, PORT)
    server.start_server()