import json, sqlite3, click, functools, os, hashlib,time, random, sys
from flask import Flask, current_app, g, session, redirect, render_template, url_for, request
from base64 import b64encode

### DATABASE FUNCTIONS ###

def connect_db():
    return sqlite3.connect(app.database)

def init_db():
    """Initializes the database with our great SQL schema"""
    conn = connect_db()
    db = conn.cursor()
    db.executescript("""

DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS notes;
DROP TABLE IF EXISTS messages;

CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assocUser INTEGER NOT NULL,
    dateWritten DATETIME NOT NULL,
    note TEXT NOT NULL,
    publicID INTEGER NOT NULL
);

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    passwordHash TEXT NOT NULL,
    passwordSalt TEXT NOT NULL
);

CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    msg TEXT NOT NULL,
    timestamp DATETIME NOT NULL
);

INSERT INTO users VALUES(null,"admin", "b236617783eccde7b018031dfef09f8e18fcb16e5ee68d56b6f1147a79d9c67bf292a67f0e25994fe28056d694144233f6ee8a0e94a7fc97407a0e88bbe11530", "eMk1/VTckNjnonWBSrcbqRjas7Z7dnSoPLaFxLswj6E=");
INSERT INTO users VALUES(null,"bernardo", "8f235d0c0123ce1c0aecb6fc91e2108e3cfab3820a693b2d05856366780b29775fcfa14eeb6e9ff3a9dc3dc81b848d5c7b136cb548a16c4a3fd437d88b4e8d90", "lKVxVD+XlsNJfkAdbwBOAG4ecX1L+rhRHw+G3aGu89k=");
INSERT INTO notes VALUES(null,2,"1993-09-23 10:10:10","hello my friend",1234567890);
INSERT INTO notes VALUES(null,2,"1993-09-23 12:10:10","i want lunch pls",1234567891);


INSERT INTO messages VALUES(null, "Group 21","Try breaking this :)", "2022-11-15 00:00:00");
INSERT INTO messages VALUES(null, "Bernardo David (8$ verified)","Wow, this is such great work! You get straight A's", "2022-11-15 00:00:00");

""")

# Hashed default users #
# admin:password
# bernardo:omgMPC


### APPLICATION SETUP ###
app = Flask(__name__)
app.database = "db.sqlite3"
app.secret_key = os.urandom(32)

### ADMINISTRATOR'S PANEL ###
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view

@app.route("/")
def index():
    if not session.get('logged_in'):
        return render_template('index.html')
    else:
        return redirect(url_for('notes'))


@app.route("/notes/", methods=('GET', 'POST'))
@login_required
def notes():
    importerror=""
    #Posting a new note:
    if request.method == 'POST':
        if request.form['submit_button'] == 'add note':
            note = request.form['noteinput']
            db = connect_db()
            c = db.cursor()
            statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,?,?,?,?);"""
            print(statement)
            c.execute(statement, (session['userid'],time.strftime('%Y-%m-%d %H:%M:%S'),note,random.randrange(1000000000, 9999999999)))
            db.commit()
            db.close()
        elif request.form['submit_button'] == 'import note':
            noteid = request.form['noteid']
            db = connect_db()
            c = db.cursor()
            statement = "SELECT * from NOTES where publicID = ?"
            c.execute(statement, [noteid])
            result = c.fetchall()
            if(len(result)>0):
                row = result[0]
                statement = """INSERT INTO notes(id,assocUser,dateWritten,note,publicID) VALUES(null,?,?,?,?);"""
                c.execute(statement, (session['userid'],row[2],row[3],row[4]))
            else:
                importerror="No such note with that ID!"
            db.commit()
            db.close()
    
    db = connect_db()
    c = db.cursor()
    statement = "SELECT * FROM notes WHERE assocUser = ?;"
    print(statement)
    c.execute(statement, [session['userid']])
    notes = c.fetchall()
    print(notes)
    
    return render_template('notes.html',notes=notes,importerror=importerror)


@app.route("/login/", methods=('GET', 'POST'))
def login():
    error = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        statement = "SELECT * FROM users WHERE username = ?;"
        c.execute(statement, [username])
        result = c.fetchall()

        # Compare user input with database hash and salt #
        if len(result) > 0:
            if check_password(password, result[0][2], result[0][3]):
                session.clear()
                session['logged_in'] = True
                session['userid'] = result[0][0]
                session['username']=result[0][1]
                return redirect(url_for('index'))
            else:
                error = "Wrong username or password!"
        else:
            error = "Wrong username or password!"
            
    return render_template('login.html',error=error)


@app.route("/register/", methods=('GET', 'POST'))
def register():
    errored = False
    usererror = ""
    passworderror = ""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = connect_db()
        c = db.cursor()
        # pass_statement = "SELECT * FROM users WHERE password = ?;"
        user_statement = "SELECT * FROM users WHERE username = ?;"
        #c.execute(pass_statement, [password])
        #if(len(c.fetchall())>0):
        #    errored = True
        #    passworderror = "That password is already in use by someone else!"

        c.execute(user_statement, [username])
        if(len(c.fetchall())>0):
            errored = True
            usererror = "That username is already in use by someone else!"

        if(not errored):

            # Hash password to avoid storing plain-text #
            salt = b64encode(os.urandom(32)).decode('utf-8')
            hash = hash_password(password, salt)

            statement = "INSERT INTO users(id,username,passwordHash,passwordSalt) VALUES(null,?,?,?);"
            print(statement)
            c.execute(statement, (username,hash,salt))
            db.commit()
            db.close()
            return f"""<html>
                        <head>
                            <meta http-equiv="refresh" content="2;url=/" />
                        </head>
                        <body>
                            <h1>SUCCESS!!! Redirecting in 2 seconds...</h1>
                        </body>
                        </html>
                        """
        
        db.commit()
        db.close()
    return render_template('register.html',usererror=usererror,passworderror=passworderror)

@app.route('/chats/', methods=('GET', 'POST'))
@login_required
def chats():
    # create function to get all chat messages and render
    importerror=""
    #Posting a new note:
    if request.method == 'POST':
        chat = request.form['chatinput']
        db = connect_db()
        c = db.cursor()
        #statement = """INSERT INTO messages(id,username,msg,timestamp) VALUES(null,?,?,?);"""
        
        #c.execute(statement, (session['username'], chat, time.strftime('%Y-%m-%d %H:%M:%S')))
       
        statement = """INSERT INTO messages(id,username,msg,timestamp) VALUES(null,'%s','%s','%s');""" %(session['username'],chat,time.strftime('%Y-%m-%d %H:%M:%S'))
        print(statement)
        c.execute(statement)
        db.commit()
        db.close()
    
    db = connect_db()
    c = db.cursor()
    statement = "SELECT * FROM messages;"
    print(statement)
    c.execute(statement)
    chats = c.fetchall()
    print(notes)
    
    
    # create function to take a message and insert into db
    
    
    return render_template('chats.html', chats=chats)

@app.route("/logout/")
@login_required
def logout():
    """Logout: clears the session"""
    session.clear()
    return redirect(url_for('index'))

def hash_password(password, salt):
    return hashlib.sha512((salt + password).encode('utf-8')).hexdigest()

def check_password(password, hash, salt):
    return hash_password(password, salt) == hash

if __name__ == "__main__":
    #create database if it doesn't exist yet
    if not os.path.exists(app.database):
        init_db()
    runport = 5000
    if(len(sys.argv)==2):
        runport = sys.argv[1]
    try:
        app.run(host='0.0.0.0', port=runport) # runs on machine ip address to make it visible on netowrk
    except:
        print("Something went wrong. the usage of the server is either")
        print("'python3 app.py' (to start on port 5000)")
        print("or")
        print("'sudo python3 app.py 80' (to run on any other port)")

