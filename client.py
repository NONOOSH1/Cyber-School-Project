# Noam Chen

# IMPORTS
import tkinter as tk
from typing import Tuple
import customtkinter as ctk
from tkinter import *
from tkinter import messagebox
from tkinter import ttk
from tkcalendar import *
import socket
import hashlib
from datetime import datetime
import re
# ==================================================

HOST = "IP ADDRESS"
PORT = 8080 # SAME PORT IN CLIENT AND THE SERVER

# Caesar Cipher (Encryption)
def caesar_cipher(text, key):
    result = ''
    # check if the the length of the string is dividable with 26, then give the key the right values
    if key > 0 and key % 26 == 0:
        key = 17
    elif key < 0 and key % 26 == 0:
        key = -17
    else:
        key = key % 26
    
    for char in text:
        if char.isalpha():  # Check if the character is an alphabet letter
            shifted = ord(char) + key
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result

# LoginPage Class
class LoginPage(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Setup
        self.geometry("400x300")
        self.title("Login Page")
        self.resizable(False, False)

        # Username Entry
        self.username_entry = ctk.CTkEntry(self,
                                           width=200,
                                           height=20,
                                           font=("Oswald", 20),
                                           placeholder_text="Username",
                                           fg_color="transparent")
        self.username_entry.place(x=100, y=40)

        # Password Entry
        self.password_entry = ctk.CTkEntry(self,
                                           width=200,
                                           height=20,
                                           font=("Oswald", 20),
                                           placeholder_text="Password",
                                           fg_color="transparent",
                                           show="*")
        self.password_entry.place(x=100, y=100)

        # Show Password Checkbutton
        self.show_password_var = ctk.BooleanVar()
        self.show_password_checkbox = ctk.CTkCheckBox(self,
                                                      text="Show Password",
                                                      variable=self.show_password_var,
                                                      command=self.toggle_password_visibility)
        self.show_password_checkbox.place(x=100, y=145)

        # Login Button
        self.Login_button = ctk.CTkButton(self,
                                          corner_radius=20,
                                          hover_color="#2f3842",
                                          width=200,
                                          border_color="red",
                                          border_width=3,
                                          text="Login",
                                          fg_color="transparent",
                                          command=self.pressed_login_button,
                                          font=("Oswald", 14),
                                          cursor = "hand2")
        self.Login_button.place(x=100, y=210)

        # Signup Page Button
        self.signup_page_button = ctk.CTkButton(self,
                                                corner_radius=20,
                                                hover_color="#2f3842",
                                                width=250,
                                                border_color="#299e5c",
                                                border_width=3,
                                                text="Do not have an account? Sign up",
                                                fg_color="transparent",
                                                command=self.pressed_signup_page,
                                                font=("Oswald", 14),
                                                cursor = "hand2")
        self.signup_page_button.place(x=75, y=250)

        # If user wants to leave
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # On Close
    def on_close(self):
        client_socket.send("Quit".encode())
        self.destroy()

    # Toggle Password Visibility
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    # Pressed Login Button
    def pressed_login_button(self):
        # get the username and password, hashing the password, send both to the server,
        # if the response is positive, go to the main note window
        username = self.username_entry.get()
        password = self.password_entry.get()
        if username != "" and password != "":
            hash = hashlib.sha256() # hash the password to be uncrackable
            hash.update(password.encode("utf-8"))
            hash = hash.hexdigest()
            message = f"Login/:{username}/:{hash}" # build the message
            client_socket.send(message.encode()) # send the message to the server and receive his response
            response = client_socket.recv(1024).decode()
            if response == "Login successful":
                self.destroy() # go to NotesPage window
                app = NotesPage(username)
                app.mainloop()
            elif response == "Login failed":
                messagebox.showerror("Error", "Wrong username or password, Try again")
            elif response == "Username does not exist":
                messagebox.showerror("Error", "Username does not exist")
        else:
            messagebox.showerror("Error", "Fill all the entries") # not everything was filled
        
    # Pressed Signup Page
    def pressed_signup_page(self): # go to the signup page window if the signup button in the login page was pressed
        self.destroy()
        app = SignupPage()
        app.mainloop()

# SignupPage Class
class SignupPage(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Setup
        self.geometry("400x400")
        self.title("Signup Page")
        self.resizable(False, False)

        # Username Entry
        self.username_entry = ctk.CTkEntry(self,
                                           width=200,
                                           height=20,
                                           font=("Oswald", 20),
                                           placeholder_text="Username",
                                           fg_color="transparent")
        self.username_entry.place(x=100, y=50)

        # Password Entry
        self.password_entry = ctk.CTkEntry(self,
                                           width=200,
                                           height=20,
                                           font=("Oswald", 20),
                                           placeholder_text="Password",
                                           fg_color="transparent",
                                           show="*")
        self.password_entry.place(x=100, y=110)

        # Show Password Checkbutton
        self.show_password_var = ctk.BooleanVar()
        self.show_password_checkbox = ctk.CTkCheckBox(self,
                                                      text="Show Password",
                                                      variable=self.show_password_var,
                                                      command=self.toggle_password_visibility)
        self.show_password_checkbox.place(x=100, y=145)

        # Confirm Password Entry
        self.confirm_password_entry = ctk.CTkEntry(self,
                                                   width=200,
                                                   height=20,
                                                   font=("Oswald", 20),
                                                   placeholder_text="Confirm Password",
                                                   fg_color="transparent",
                                                   show="*")
        self.confirm_password_entry.place(x=100, y=190)

        # Show Confirm Password Checkbutton
        self.show_confirm_password_var = ctk.BooleanVar()
        self.show_confirm_password_checkbox = ctk.CTkCheckBox(self,
                                                              text="Show Confirm Password",
                                                              variable=self.show_confirm_password_var,
                                                              command=self.toggle_confirm_password_visibility)
        self.show_confirm_password_checkbox.place(x=100, y=225)

        # Signup Button
        self.Signup_button = ctk.CTkButton(self,
                                           corner_radius=20,
                                           hover_color="#2f3842",
                                           width=200,
                                           border_color="red",
                                           border_width=3,
                                           text="Signup",
                                           fg_color="transparent",
                                           font=("Oswald", 14),
                                           cursor = "hand2",
                                           command=self.pressed_signup_button)
        self.Signup_button.place(x=100, y=310)

        # Login Page Button
        self.login_page_button = ctk.CTkButton(self,
                                               corner_radius=20,
                                               hover_color="#2f3842",
                                               width=250,
                                               border_color="#299e5c",
                                               border_width=3,
                                               text="Already have an account? Log in",
                                               fg_color="transparent",
                                               font=("Oswald", 14),
                                               command=self.pressed_login_page,
                                               cursor = "hand2")
        self.login_page_button.place(x=75, y=350)

        # If user wants to leave
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # On Close
    def on_close(self):
        client_socket.send("Quit".encode())
        self.destroy()

    # Toggle Password Visibility
    def toggle_password_visibility(self):
        if self.show_password_var.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    # Toggle Confirm Password Visibility
    def toggle_confirm_password_visibility(self):
        if self.show_confirm_password_var.get():
            self.confirm_password_entry.configure(show="")
        else:
            self.confirm_password_entry.configure(show="*")

    # Pressed Signup Button
    def pressed_signup_button(self):
        # get the username, password and the confirm password
        username = self.username_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()
        # check if the username, password and confirm password are valid
        if username != "" and password != "" and confirm_password != "":
            # check if the passwords are identical
            if password == confirm_password:
                if self.check_password_strength(password):
                    hash = hashlib.sha256() # has the password to be uncrackable
                    hash.update(password.encode("utf-8"))
                    hash = hash.hexdigest()
                    message = f"Signup/:{username}/:{hash}" # build the message
                    client_socket.send(message.encode()) # send the message to the server and receive his response
                    response = client_socket.recv(1024).decode()

                    if response == "Signup successful":
                        messagebox.showinfo("Success", "Signup successful")
                        self.pressed_login_page()
                    elif response == "Username taken":
                        messagebox.showerror("Error", "Username is already taken, Try again")
                else:
                    messagebox.showerror("Error", "Password is not strong enough.\nThe password must include:\n- Uppercase & Lowercase letters\n- Digits\n- Chars")
            else:
                messagebox.showerror("Error", "Passwords do not match")
        else:
            messagebox.showerror("Error", "Invalid credentials")
            
    # Check Password Strength
    def check_password_strength(self, password):
        if len(password) < 8:
            #return False
            return True
        
        # Character type checks
        has_uppercase = re.search(r"[A-Z]", password) is not None
        has_lowercase = re.search(r"[a-z]", password) is not None
        has_digit = re.search(r"\d", password) is not None
        has_special_char = re.search(r"[!@#$%^&*()_+{}\[\]:;<>,.?~]", password) is not None
        
        # Overall strength check
        return has_uppercase and has_lowercase and has_digit and has_special_char
        #return True

    # Pressed Login Page
    def pressed_login_page(self):
        self.destroy()
        app = LoginPage()
        app.mainloop()

# NotesPage Class
class NotesPage(ctk.CTk):
    def __init__(self, name):
        super().__init__()

        self.name = name

        # Setup
        self.title(name)
        self.geometry("800x600")
        self.config(bg="#09112e")
        self.resizable(False, False)
        
        # Blank Square
        self.blank = ctk.CTkButton(self,
                                   text="",
                                   bg_color="#09112e",
                                   fg_color="#09112e",
                                   height=1)
        self.blank.pack(side="bottom", fill="x", pady=20)

        # Log out button
        self.log_out_button = ctk.CTkButton(self,
                                            text="Log out",
                                            width=0,
                                            bg_color="#09112e",
                                            fg_color="#09112e",
                                            text_color="red",
                                            hover_color="#09112e",
                                            font=("Oswald", 14),
                                            command=self.pressed_log_out_button)
        self.log_out_button.place(x=0, y=0)

        # Title Label (ToDoLi title)
        self.title_label = ctk.CTkLabel(self,
                                        text="ToDoLi",
                                        bg_color="#09112e",
                                        font=("Calibari", 18, "bold"))
        self.title_label.pack(pady=20)
        
        # Header Label
        self.header_label = ctk.CTkLabel(self,
                                         text="Task's Name:",
                                         bg_color="#09112e",
                                         font=("Comic Sans MS", 14, "bold"))
        self.header_label.place(x=10, y=50)
        
        # Header Entry
        self.header_entry = ctk.CTkEntry(self,
                                         placeholder_text="Enter task name here",
                                         font=("Oswald", 18),
                                         width=250,
                                         fg_color="#0f2340",
                                         border_color="#fff",
                                         corner_radius=7)
        self.header_entry.place(x=10, y=80)
        
        # Header Label
        self.content_label = ctk.CTkLabel(self,
                                          text="Content:",
                                          bg_color="#09112e",
                                          font=("Comic Sans MS", 14, "bold"))
        self.content_label.place(x=10, y=120)
        
        # Content Entry
        self.content_entry = ctk.CTkEntry(self,
                                          placeholder_text="Enter content here",
                                          font=("Oswald", 18),
                                          width=250,
                                          fg_color="#0f2340",
                                          border_color="#fff",
                                          corner_radius=7)
        self.content_entry.place(x=10, y=150)

        # Add Button
        self.add_button = ctk.CTkButton(self,
                                        text="Add",
                                        width=250,
                                        bg_color="#09112e",
                                        fg_color="green",
                                        hover_color="#1a5c2b",
                                        corner_radius=10,
                                        cursor="hand2",
                                        font=("Oswald", 14, "bold"),
                                        command=self.add_task)
        self.add_button.place(x=10, y=450)

        # Delete Button
        self.delete_button = ctk.CTkButton(self,
                                           text="Delete",
                                           width=250,
                                           bg_color="#09112e",
                                           fg_color="red",
                                           hover_color="#750418",
                                           corner_radius=10,
                                           cursor="hand2",
                                           font=("Oswald", 14, "bold"),
                                           command=self.delete_task)
        self.delete_button.place(x=10, y=490)

        # View Button
        self.view_button = ctk.CTkButton(self,
                                         text="View/Edit",
                                         width=250,
                                         bg_color="#09112e",
                                         fg_color="#115eab",
                                         hover_color="#1d3854",
                                         corner_radius=10,
                                         cursor="hand2",
                                         font=("Oswald", 14, "bold"),
                                         command=self.view_task)
        self.view_button.place(x=10, y=530)

        # Calendar
        self.cal = Calendar(self,
                            selectmode='day',
                            date_pattern='dd-mm-yyyy',
                            font=("Arial", 10),
                            width=200,
                            height=200)
        self.cal.place(x=10, y=215)

        # Treeview
        style = ttk.Style(self)

        style.theme_use("clam")
        style.configure("Treeview",
                        font=("Oswald", 12, "bold"),
                        foreground="#030303",
                        background="white",
                        fieldbackground="white")
        style.map("Treeview", background=[("selected", "#85afed")])

        self.tree = ttk.Treeview(self)

        self.tree["columns"] = ("Task's Name", "Date")

        self.tree.column("#0", width=0, stretch=tk.NO)
        self.tree.column("Task's Name", anchor=tk.W, width=250)
        self.tree.column("Date", anchor=tk.CENTER, width=250)

        self.tree.heading("Task's Name", text="Task's Name")
        self.tree.heading("Date", text="Date")

        # Create a vertical scrollbar
        self.scrollbar = ctk.CTkScrollbar(self, command=self.tree.yview)
        self.scrollbar.pack(side="right", fill="y")
        
        self.tree.pack(side="right", fill="y")

        # Connect the listbox to the scrollbar
        self.tree.config(yscrollcommand=self.scrollbar.set)

        # LOAD ALL THE NOTES
        self.load()

        # If user wants to leave
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    # On Close
    def on_close(self):
        client_socket.send("Quit".encode())
        self.destroy()
    
    # Load / Reload all tasks
    def load(self):
        # Remove all the tasks
        self.tree.delete(*self.tree.get_children())
        self.tree.tag_configure("late", foreground="red")

        # send the name of the user to the server
        # and receive all of his tasks
        client_socket.send(self.name.encode())
        resp = client_socket.recv(1024).decode()

        if resp != "None":
            tasks = resp.split("/:") # split all the tasks

            for item in tasks:
                header, date = item.rsplit(" ", 1)
                
                current_date = datetime.now().date()
                input_date = datetime.strptime(date, "%d-%m-%Y")
                
                # check if the task's date is smaller then the current date
                # if yes, the task will be count as "late" and will be painted in red 
                if input_date.date() < current_date:
                    self.tree.insert("", 0, values=(header, date))
                    self.tree.item(self.tree.get_children()[0], tags=("late",))
                else:
                    self.tree.insert("", END, values=(header, date))
                    

    # Pressed Log Out Button
    def pressed_log_out_button(self):
        self.destroy()
        app = LoginPage()
        app.mainloop()
    
    # Add Task
    def add_task(self):
        task = self.header_entry.get()
        content = self.content_entry.get()
        content = caesar_cipher(content, len(content))
        if task:
            if content:
                date = str(self.cal.get_date())
                message = f"Add/:{self.name}/:{task}/:{date}/:{content}" # build the message
                # send the message to the server and get the response
                client_socket.send(message.encode())
                response = client_socket.recv(1024).decode()

                if response == "Task added":
                    self.header_entry.delete(0, END) # delete the entries
                    self.content_entry.delete(0, END)
                    self.load() # show all the tasks
                    messagebox.showinfo("Success", f"'{task}' added successfully")
                elif response == "The name for the task has been taken":
                    messagebox.showerror("Error", "The name for the task has been taken, Try again")
            else:
                messagebox.showerror("Error", "Enter content for the task")
        else:
            messagebox.showerror("Error", "Enter a name for the task")

    # Delete Task
    def delete_task(self):
        selected = self.tree.selection() # get the selected task
        curItem = self.tree.focus()
        item_values = self.tree.item(curItem)["values"]
        if selected and item_values:
            header, date = item_values[0], item_values[1]
            message = f"Delete/:{self.name}/:{header}/:{date}" # build the message
            # send the message to the server and get the response
            client_socket.send(message.encode())
            response = client_socket.recv(1024).decode()

            if response == "Task deleted":
                self.tree.delete(selected) # delete the selected task
                messagebox.showinfo("Success", "Task deleted successfully")
            else:
                messagebox.showerror("Error", "Task was not deleted")
        else:
            messagebox.showerror("Error", "Choose task to delete")
        
        self.load() # load all the tasks
    
    # View Task
    def view_task(self):
        selected = self.tree.selection() # select the note i want to change (if i pressed any)
        curItem = self.tree.focus()
        item_values = self.tree.item(curItem)["values"]
        if selected and item_values:
            header, date = item_values[0], item_values[1] # split the header and the date
            message = f"View/:{self.name}/:{header}/:{date}" # build the message
            client_socket.send(message.encode()) # send
            response = client_socket.recv(1024).decode() # receive
            response = caesar_cipher(response, -len(response))
            self.destroy() # destroy the current window and open the edit window
            edit_window = ViewWindow(self.name, header, date, response)
            edit_window.mainloop()
        else:
            messagebox.showerror("Error", "Choose task to view")

# ViewWindow CLASS
class ViewWindow(ctk.CTk):
    def __init__(self, name, header, date, response):
        super().__init__()

        # set the name and header so i can use them in function
        self.name = name
        self.header = header
        
        # Setup
        self.geometry("400x300")
        self.title(f"{header} ({date})")

        # Text Entry
        self.text_entry = ctk.CTkTextbox(self, height=10, width=50) # you can adjust height and width as needed
        self.text_entry.pack(fill=ctk.BOTH, expand=True, padx=10, pady=10) # fill X-axis and add padding

        # insert into the text entry the content of the note
        self.text_entry.insert("1.0", response)

        # Save Button
        self.save_button = ctk.CTkButton(self,
                                         corner_radius=20,
                                         hover_color="#2f3842",
                                         width=200,
                                         border_color="red",
                                         border_width=3,
                                         text="Save",
                                         fg_color="transparent",
                                         font=("Oswald", 14),
                                         cursor = "hand2",
                                         command=self.save_button_clicked)
        self.save_button.pack(side=ctk.BOTTOM, pady=10) # place at bottom center with padding

        # Calender
        self.cal = DateEntry(self, width=12, date_pattern="dd/mm/yyyy")
        self.cal.pack(side=ctk.BOTTOM, pady=10)

        # change the date from dd-mm-yyyy to dd/mm/yyyy
        day, month, year = date.split("-")
        self.cal.set_date(date=f"{day}/{month}/{year}")

        # if user wants to leave in the middle of editing
        self.protocol("WM_DELETE_WINDOW", self.on_close)
    
    # On Close
    def on_close(self):
        self.destroy()
        app = NotesPage(self.name)
        app.mainloop()

    # Save Button Clicked
    def save_button_clicked(self):
        content = self.text_entry.get("1.0", "end-1c")
        content = caesar_cipher(content, len(content))
        year, month, day = str(self.cal.get_date()).split("-")
        date = day + "-" + month + "-" + year
        message = f"Edit/:{self.name}/:{self.header}/:{content}/:{date}" # build the message

        # destroy the window
        self.destroy()

        # send & get to/from the server
        client_socket.send(message.encode())
        response = client_socket.recv(1024).decode()

        if response == "Success":
            messagebox.showinfo("Success", "Content saved")
        else:
            messagebox.showerror("ERROR", "Something went wrong")
        
        # switching window to NotePage window
        app = NotesPage(self.name)
        app.mainloop()

# START
if __name__ == "__main__":

    # set up the server
    server_address = (HOST, PORT)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(server_address)
    
    # start the main program
    app = LoginPage()
    app.mainloop()