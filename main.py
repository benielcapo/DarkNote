import bcrypt
import getpass
import tkinter
import os
import tkinter.messagebox
import tkinter.filedialog
import cryptography.hazmat.primitives.kdf.pbkdf2
import cryptography.hazmat.primitives
import cryptography.fernet
import base64
import tkinter.simpledialog
import sys
import ctypes
import subprocess

USER = getpass.getuser()
BASE_PATH = fr"C:\Users\{USER}\AppData\Local\DarkNote"
PASS_PATH = fr"C:\Users\{USER}\AppData\Local\DarkNote\pass.txt"
NOTES_PATH = fr"C:\Users\{USER}\AppData\Local\DarkNote\Notes"
SALT = bcrypt.gensalt()
FERNET_SALT = b"CONSTANT_SALT"
DARKNOTE_EXTENSION = ".dn"
PASSWORD = ""
PAD_CHARACTER = "="

os.makedirs(BASE_PATH, exist_ok=True)
os.makedirs(NOTES_PATH, exist_ok=True)

class WidgetTypes:
    load_file = "load_file"
    text_editor = "text_editor"
    enter_password = "enter_password"
    text_editor_create = "text_editor_create"

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except AttributeError:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class CustomRoot(tkinter.Tk):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        myappid = 'com.darknote.darknote'
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        self.title("DarkNote")
        self.iconbitmap(resource_path(os.path.join("Assets", "icon.ico")))

class NoteData:
    path = ""

def get_fernet_key(password: str) -> bytes:
    password_bytes = password.encode()
    kdf = cryptography.hazmat.primitives.kdf.pbkdf2.PBKDF2HMAC(
        algorithm=cryptography.hazmat.primitives.hashes.SHA256(),
        length=32,
        salt=FERNET_SALT,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password_bytes))
    return key

def get_default_widget(window_width = 300, window_height = 400, background_color = "black", resizable = False):
    root = CustomRoot()
    root.configure(background=background_color)
    root.resizable(resizable, resizable)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    geometry = f"{window_width}x{window_height}+{x}+{y}"
    root.geometry(geometry)
    return root

def pad(s, chars):
    new_s = s
    while len(new_s) < chars:
        new_s += PAD_CHARACTER
    return new_s

def get_note_content(path):
    try:
        with open(path, "rb") as file:
            content = file.read()
        key = get_fernet_key(PASSWORD)
        f = cryptography.fernet.Fernet(key)
        decrypted = f.decrypt(content)
        text = decrypted.decode()
        return text
    except Exception as e:
        tkinter.messagebox.showerror("Error reading note", e)

def save_note(path, text):
    key = get_fernet_key(PASSWORD)
    f = cryptography.fernet.Fernet(key)
    encrypted = f.encrypt(text.encode())
    with open(path, "wb") as file:
        file.write(encrypted)

def delete_notes():
    if os.path.exists(NOTES_PATH):
        for filename in os.listdir(NOTES_PATH):
            file_path = os.path.join(NOTES_PATH, filename)
            if os.path.isfile(file_path):
                os.remove(file_path)

def pass_is_ok(password):
    message = True
    if password == "":
        message = "Password is empty!"
    if len(password) > 30:
        message = "Password must be 30 or less characters!"
    return message

def create_password(pass_input, root):
    password = pass_input.get()
    ok_pass = pass_is_ok(password)
    if isinstance(ok_pass, str):
        tkinter.messagebox.showerror("Bad password", ok_pass)
        return
    encrypted = bcrypt.hashpw(password.encode(), SALT).decode()
    with open(PASS_PATH, "w+") as file:
        file.write(encrypted)
    root.destroy()
    main()

def verify_password(password):
    with open(PASS_PATH) as file:
        hashed = file.read()
    return bcrypt.checkpw(password.encode(), hashed.encode())

def choose_new_pass():
    delete_notes()
    root = CustomRoot()
    root.configure(background="black")
    root.resizable(False, False)
    label = tkinter.Label(root, text="Create password", font=("Arial", 20), background="black", fg="white")
    label.pack(pady=50)
    pass_input = tkinter.Entry(root, relief="flat", highlightthickness=0, bd=0, font=("Arial", 15), show="*")
    pass_input.pack(pady=20)
    button = tkinter.Button(root, text="Create", background="#ADD8E6", relief="flat", activebackground="#03BDF9", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=lambda: create_password(pass_input, root))
    button.pack(pady=30)
    screen_width = root.winfo_screenwidth()
    screen_height = root.winfo_screenheight()
    window_width = 300
    window_height = 400
    x = (screen_width - window_width) // 2
    y = (screen_height - window_height) // 2
    geometry = f"{window_width}x{window_height}+{x}+{y}"
    root.geometry(geometry)
    root.mainloop()

def load_widget(widget_type, data: NoteData | None = None):
    if widget_type == WidgetTypes.text_editor:
        def save():
            written_text = text.get("1.0", "end-1c")
            root.destroy()
            save_note(note_path, written_text)
        def run_py_script():
            written_text = text.get("1.0", "end-1c")
            try:
                subprocess.Popen(['python', '-c', written_text], creationflags=subprocess.CREATE_NEW_CONSOLE)
            except Exception as err:
                tkinter.messagebox.showerror("Error compiling: " + str(err))
        root = get_default_widget(window_width=800, window_height=600, resizable=True)
        container = tkinter.Frame(root, bg="#020E20")
        container.pack(side="right", fill="both", expand=True)
        text = tkinter.Text(
            root,
            bg="black",
            fg="white",
            insertbackground="white",
            highlightthickness=0,
            bd=0,
        )
        text.pack(side="left", fill="both", expand=True, padx=(0, 50), pady=0)
        note_path = data.path
        content = get_note_content(note_path)
        text.insert("1.0", content)
        save_button = tkinter.Button(container, text="Save", background="#AAFFB8", relief="flat", activebackground="#007A10", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=save)
        save_button.pack(side="top", fill="x")
        py_run = tkinter.Button(container, text="Run py script", background="#00FFFF", relief="flat", activebackground="#EEFF00", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=run_py_script)
        py_run.pack(side="top", fill="x")
        root.mainloop()
    elif widget_type == WidgetTypes.load_file:
        def choose_file():
            file_path = tkinter.filedialog.askopenfilename(
                initialdir=NOTES_PATH,
                title="Select a file",
                filetypes=[("DarkNote Text file", f"*{DARKNOTE_EXTENSION}")]
            )
            if file_path == "":
                return
            if not file_path.endswith(DARKNOTE_EXTENSION):
                tkinter.messagebox.showerror("Error reading note", "File is not a valid note")
                return
            note_data = NoteData()
            note_data.path = file_path
            load_widget(WidgetTypes.text_editor, note_data)
        def create_file():
            load_widget(WidgetTypes.text_editor_create)
        root = get_default_widget(window_width=800, window_height=600, resizable=True)
        button = tkinter.Button(root, text="Load note", background="#ADD8E6", relief="flat", activebackground="#03BDF9", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=choose_file)
        button_create = tkinter.Button(root, text="Create note", background="#BEF7A3", relief="flat", activebackground="#005E05", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=create_file)
        button_create.pack(pady=40)
        button.pack(pady=30)
        root.mainloop()
    elif widget_type == WidgetTypes.enter_password:
        def handle():
            password = pass_input.get()
            if verify_password(password):
                global PASSWORD
                PASSWORD = password
                root.destroy()
                load_widget(WidgetTypes.load_file)
            else:
                tkinter.messagebox.showerror("Incorrect password", "The password you entered is incorrect")
        def reset():
            root.destroy()
            os.remove(PASS_PATH)
            choose_new_pass()
        root = get_default_widget(window_width=800, window_height=600, resizable=True)
        label = tkinter.Label(root, text="Submit password", font=("Arial", 20), background="black", fg="white")
        label.pack(pady=50)
        pass_input = tkinter.Entry(root, relief="flat", highlightthickness=0, bd=0, font=("Arial", 15), show="*")
        pass_input.pack(pady=20)
        button = tkinter.Button(root, text="Submit", background="#ADD8E6", relief="flat", activebackground="#03BDF9", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=handle)
        button.pack(pady=30)
        button_reset = tkinter.Button(root, text="Reset", background="#D67272", relief="flat", activebackground="#F90303", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=reset)
        button_reset.pack()
        root.mainloop()
    elif widget_type == WidgetTypes.text_editor_create:
        def save():
            written_text = text.get("1.0", "end-1c")
            if written_text == "":
                tkinter.messagebox.showerror("Error saving note", "Note cant be empty")
                return
            user_input = tkinter.simpledialog.askstring("Input", "Enter file name: ")
            if user_input is not None and user_input != "":
                note_path = NOTES_PATH + "\\" + user_input + DARKNOTE_EXTENSION
                if os.path.exists(note_path):
                    tkinter.messagebox.showerror("Error saving note", "A note with that name already exists")
                    return
                root.destroy()
                save_note(note_path, written_text)
        def run_py_script():
            written_text = text.get("1.0", "end-1c")
            try:
                subprocess.Popen(['python', '-c', written_text], creationflags=subprocess.CREATE_NEW_CONSOLE)
            except Exception as err:
                tkinter.messagebox.showerror("Error compiling: " + str(err))
        root = get_default_widget(window_width=800, window_height=600, resizable=True)
        container = tkinter.Frame(root, bg="#020E20")
        container.pack(side="right", fill="both", expand=True)
        text = tkinter.Text(
            root,
            bg="black",
            fg="white",
            insertbackground="white",
            highlightthickness=0,
            bd=0,
        )
        text.pack(fill="both", expand=True, padx=(0, 50), pady=0)
        save_button = tkinter.Button(container, text="Save", background="#AAFFB8", relief="flat", activebackground="#007A10", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=save)
        save_button.pack(side="top", fill="x")
        py_run = tkinter.Button(container, text="Run py script", background="#00FFFF", relief="flat", activebackground="#EEFF00", highlightthickness=0, bd=0, activeforeground="black", overrelief="flat", font=("Arial", 20), command=run_py_script)
        py_run.pack(side="top", fill="x")
        root.mainloop()

def main():
    if not os.path.exists(PASS_PATH):
        choose_new_pass()
    load_widget(WidgetTypes.enter_password)

if __name__ == "__main__":
    main()