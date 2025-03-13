from flask import Flask, render_template, request, redirect, url_for, flash, session
from werkzeug.utils import secure_filename
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.secret_key = 'your_secret_key'

UPLOAD_FOLDER = 'static/uploads/'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# Hash password function
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Database initialization
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Create entries table with user_id
    c.execute('''CREATE TABLE IF NOT EXISTS entries (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    rank_required TEXT NOT NULL,
                    region TEXT NOT NULL,
                    select_type TEXT NOT NULL,
                    user_id INTEGER REFERENCES users(id)
                )''')

    # Create users table (Fixed)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    email TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    isonline BOOLEAN NOT NULL DEFAULT FALSE
                )''')

    # Modify chats table to associate with entries
    c.execute('''CREATE TABLE IF NOT EXISTS chats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entry_id INTEGER REFERENCES entries(id),  -- NEW COLUMN
                    user1_id INTEGER REFERENCES users(id),
                    user2_id INTEGER REFERENCES users(id),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

    # Create messages table
    c.execute('''CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    chat_id INTEGER REFERENCES chats(id),
                    sender_id INTEGER REFERENCES users(id),
                    message TEXT NOT NULL,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )''')

    # Create profile table
    c.execute('''CREATE TABLE IF NOT EXISTS profile (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER REFERENCES users(id),
                    upload_banner TEXT,
                    upload_profile TEXT,
                    bio TEXT,
                    games TEXT,
                    rank TEXT,
                    tag TEXT
                )''')

    conn.commit()
    conn.close()


@app.route('/')
def index():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Fetch entries with usernames, tags, and banners
    c.execute("""
        SELECT entries.id, entries.title, entries.description, entries.rank_required,
               entries.region, entries.select_type, users.username,
               COALESCE(profile.upload_banner, 'default_banner.jpg')
        FROM entries
        JOIN users ON entries.user_id = users.id
        LEFT JOIN profile ON users.id = profile.user_id
    """)
    entries = c.fetchall()

    # Fetch users with their online status and tags
    c.execute("""
        SELECT users.id, users.username, COALESCE(profile.tag, '0000'), users.isonline
        FROM users
        LEFT JOIN profile ON users.id = profile.user_id
    """)
    users = c.fetchall()

    conn.close()
    return render_template('index.html', entries=entries, users=users)



# Add entry route
@app.route('/add', methods=['GET', 'POST'])
def add_entry():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        rank_required = request.form['rank_required']
        region = request.form['region']
        select_type = request.form['select_type']
        user_id = session['user_id']  # Get user ID from session

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("INSERT INTO entries (title, description, rank_required, region, select_type, user_id) VALUES (?, ?, ?, ?, ?, ?)",
                  (title, description, rank_required, region, select_type, user_id))
        conn.commit()
        conn.close()

        flash("Entry added successfully!")
        return redirect(url_for('index'))
    return render_template('add_entry.html')

# User registration route
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = hash_password(request.form['password'])

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, email, password, isonline) VALUES (?, ?, ?, ?)",
                      (username, email, password, False))
            conn.commit()
            flash("Registration successful! Please log in.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash("Username or email already exists.")
        finally:
            conn.close()
    return render_template('register.html')

# User login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)

        conn = sqlite3.connect('database.db')
        c = conn.cursor()

        # Fetch user along with tag from profile
        c.execute("""
            SELECT users.id, users.username, users.password, COALESCE(profile.tag, '0000')
            FROM users
            LEFT JOIN profile ON users.id = profile.user_id
            WHERE users.username = ?
        """, (username,))
        user = c.fetchone()

        if user and user[2] == hashed_password:
            session['user_id'] = user[0]
            session['username'] = user[1]
            session['tag'] = user[3]  # Store tag in session

            # Set user online
            c.execute("UPDATE users SET isonline = TRUE WHERE id = ?", (user[0],))
            conn.commit()

            flash('Login successful!', 'success')
            conn.close()
            return redirect(url_for('add_entry'))
        else:
            flash('Invalid username or password', 'error')

        conn.close()

    return render_template('login.html')


# User logout route
@app.route('/logout')
def logout():
    if 'user_id' in session:
        # Update isonline status
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute("UPDATE users SET isonline = FALSE WHERE id = ?", (session['user_id'],))
        conn.commit()
        conn.close()

        session.pop('user_id', None)
        session.pop('username', None)
        flash("You have been logged out.")
    return redirect(url_for('index'))

@app.route('/entry/<int:entry_id>')
def view_entry(entry_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Fetch entry details with username
    c.execute("""
        SELECT entries.title, entries.description, entries.rank_required,
               entries.region, entries.select_type, users.username
        FROM entries
        JOIN users ON entries.user_id = users.id
        WHERE entries.id = ?
    """, (entry_id,))

    entry = c.fetchone()
    conn.close()

    if entry:
        return render_template('view_entry.html', entry=entry)
    else:

        return redirect(url_for('index'))

@app.route('/connect/<int:entry_id>')
def connect(entry_id):
    if 'user_id' not in session:
        flash("You must be logged in to join a chat room.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Check if a chat room already exists for this entry
    c.execute("SELECT id FROM chats WHERE entry_id = ?", (entry_id,))
    chat = c.fetchone()

    if not chat:
        # Create a new chat room for this entry
        c.execute("INSERT INTO chats (entry_id, user1_id) VALUES (?, ?)", (entry_id, user_id))
        conn.commit()
        chat_id = c.lastrowid
    else:
        chat_id = chat[0]  # Use existing chat room

    conn.close()

    # Redirect user to the chat room
    return redirect(url_for('chat', chat_id=chat_id))


@app.route('/chat/<int:chat_id>')
def chat(chat_id):
    if 'user_id' not in session:
        flash("You must be logged in to chat.")
        return redirect(url_for('login'))

    user_id = session['user_id']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Fetch chat creator
    c.execute("SELECT user1_id FROM chats WHERE id = ?", (chat_id,))
    chat_creator = c.fetchone()

    if not chat_creator:
        flash("Chat not found.")
        return redirect(url_for('profile'))

    creator_id = chat_creator[0]

    # Fetch messages between user and chat creator
    c.execute("""
        SELECT messages.message, messages.sent_at, users.username,
               COALESCE(profile.upload_profile, 'default_profile.jpg')
        FROM messages
        JOIN users ON messages.sender_id = users.id
        LEFT JOIN profile ON users.id = profile.user_id
        WHERE messages.chat_id = ?
        ORDER BY messages.sent_at ASC
    """, (chat_id,))
    messages = c.fetchall()

    # Fetch the creator's username
    c.execute("SELECT username FROM users WHERE id = ?", (creator_id,))
    creator_username = c.fetchone()[0]

    # Fetch the current user's username
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    current_user = c.fetchone()[0]

    # Fetch the entry title related to the chat
    c.execute("""
        SELECT entries.title FROM entries
        JOIN chats ON entries.id = chats.entry_id
        WHERE chats.id = ?
    """, (chat_id,))
    entry = c.fetchone()

    conn.close()

    return render_template(
        'chat.html', chat_id=chat_id, messages=messages, entry=entry,
        current_user=current_user, creator_username=creator_username
    )


@app.route('/send_message/<int:chat_id>', methods=['POST'])
def send_message(chat_id):
    if 'user_id' not in session:
        flash("You must be logged in to send messages.")
        return redirect(url_for('login'))

    message = request.form['message']
    sender_id = session['user_id']

    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Insert message with timestamp
    c.execute("INSERT INTO messages (chat_id, sender_id, message, sent_at) VALUES (?, ?, ?, datetime('now'))",
              (chat_id, sender_id, message))

    conn.commit()
    conn.close()

    return redirect(url_for('chat', chat_id=chat_id))

@app.route('/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'user_id' not in session:
        flash("You must be logged in to edit your profile.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    if request.method == 'POST':
        username = request.form.get('username', '')
        bio = request.form.get('bio', '')
        games = request.form.get('games', '')
        rank = request.form.get('rank', '')
        tag = request.form.get('tag', '')

        # Handle image uploads (optional)
        banner_filename = None
        profile_filename = None

        if 'upload_banner' in request.files:
            banner_file = request.files['upload_banner']
            if banner_file and allowed_file(banner_file.filename):
                banner_filename = secure_filename(banner_file.filename)
                banner_file.save(os.path.join(app.config['UPLOAD_FOLDER'], banner_filename))

        if 'upload_profile' in request.files:
            profile_file = request.files['upload_profile']
            if profile_file and allowed_file(profile_file.filename):
                profile_filename = secure_filename(profile_file.filename)
                profile_file.save(os.path.join(app.config['UPLOAD_FOLDER'], profile_filename))

        # Update username (check for conflicts)
        try:
            c.execute("UPDATE users SET username = ? WHERE id = ?", (username, user_id))
        except sqlite3.IntegrityError:
            flash("Username already taken, please choose another.")
            conn.close()
            return redirect(url_for('profile'))

        # Update or create profile
        c.execute("SELECT * FROM profile WHERE user_id = ?", (user_id,))
        profile = c.fetchone()

        if profile:
            c.execute("""
                UPDATE profile SET bio = ?, games = ?, rank = ?, tag = ?,
                    upload_banner = COALESCE(?, upload_banner),
                    upload_profile = COALESCE(?, upload_profile)
                WHERE user_id = ?
            """, (bio, games, rank, tag, banner_filename, profile_filename, user_id))
        else:
            c.execute("""
                INSERT INTO profile (user_id, upload_banner, upload_profile, bio, games, rank, tag)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (user_id, banner_filename, profile_filename, bio, games, rank, tag))

        conn.commit()
        conn.close()

        # Update session username
        session['username'] = username

        flash("Profile updated successfully!")
        return redirect(url_for('profile'))

    # Pre-load existing data for the form
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    username = c.fetchone()[0]

    c.execute("SELECT * FROM profile WHERE user_id = ?", (user_id,))
    profile = c.fetchone()

    if not profile:
        profile = (user_id, None, None, "", "", "", "")

    conn.close()

    return render_template('edit_profile.html', profile=profile, username=username)

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        flash("You must be logged in to view your profile.")
        return redirect(url_for('login'))

    user_id = session['user_id']
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Fetch username
    c.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if not user:
        flash("User not found.")
        return redirect(url_for('index'))

    username = user[0]

    # Fetch profile with default values
    c.execute("SELECT upload_banner, upload_profile, bio, games, rank, COALESCE(tag, '#0000') FROM profile WHERE user_id = ?", (user_id,))
    profile_data = c.fetchone()

    profile = {
        'upload_banner': profile_data[0] if profile_data and profile_data[0] else 'default_banner.jpg',
        'upload_profile': profile_data[1] if profile_data and profile_data[1] else 'default_profile.jpg',
        'bio': profile_data[2] if profile_data else '',
        'games': profile_data[3] if profile_data else '',
        'rank': profile_data[4] if profile_data else '',
        'tag': profile_data[5] if profile_data else '#0000'  # Default tag
    }

    # Chat history (previous conversations)
    c.execute("""
        SELECT chats.id, users.username, COALESCE(profile.upload_profile, 'default_profile.jpg'),
               entries.title, messages.message, messages.sent_at
        FROM messages
        JOIN chats ON messages.chat_id = chats.id
        JOIN entries ON chats.entry_id = entries.id
        JOIN users ON messages.sender_id = users.id
        LEFT JOIN profile ON users.id = profile.user_id
        WHERE messages.chat_id IN (
            SELECT chat_id
            FROM messages
            WHERE sender_id != ?
            GROUP BY chat_id
            HAVING MAX(sent_at)
        )
        AND messages.sender_id != ?
        ORDER BY messages.sent_at DESC
    """, (user_id, user_id))

    chat_history = c.fetchall()

    conn.close()

    return render_template('profile.html', profile=profile, username=username, is_owner=True, chat_history=chat_history)


@app.route('/profile/<int:user_id>')
def view_profile(user_id):
    conn = sqlite3.connect('database.db')
    c = conn.cursor()

    # Fetch user profile details
    c.execute("""
        SELECT users.username,
               COALESCE(profile.upload_banner, 'default_banner.jpg'),
               COALESCE(profile.upload_profile, 'default_profile.jpg'),
               COALESCE(profile.bio, 'No bio available'),
               COALESCE(profile.games, 'Not specified'),
               COALESCE(profile.rank, 'Unranked'),
               COALESCE(profile.tag, '0000'),
               users.isonline
        FROM users
        LEFT JOIN profile ON users.id = profile.user_id
        WHERE users.id = ?
    """, (user_id,))
    profile = c.fetchone()

    # Fetch recent chat history
    c.execute("""
        SELECT chats.id, users.username, COALESCE(profile.upload_profile, 'default_profile.jpg'),
               entries.title, messages.message, messages.sent_at
        FROM messages
        JOIN chats ON messages.chat_id = chats.id
        JOIN entries ON chats.entry_id = entries.id
        JOIN users ON messages.sender_id = users.id
        LEFT JOIN profile ON users.id = profile.user_id
        WHERE messages.chat_id IN (
            SELECT chat_id FROM messages WHERE sender_id != ? GROUP BY chat_id HAVING MAX(sent_at)
        )
        AND messages.sender_id != ?
        ORDER BY messages.sent_at DESC
    """, (user_id, user_id))
    chat_history = c.fetchall()

    # Fetch all users with online status and tags
    c.execute("""
        SELECT users.id, users.username, COALESCE(profile.tag, '0000'), users.isonline
        FROM users
        LEFT JOIN profile ON users.id = profile.user_id
    """)
    users = c.fetchall()

    conn.close()

    if profile:
        return render_template('view_profile.html', profile=profile, chat_history=chat_history, users=users)
    else:
        flash("User profile not found.")
        return redirect(url_for('index'))


# Run the application
if __name__ == '__main__':
    init_db()
    app.run(debug=True)
