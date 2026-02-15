
from flask import Flask, render_template, request, redirect, flash, session, url_for
import sqlite3
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = 'supersecretkey'
bcrypt = Bcrypt(app)
# Home route
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')






# Database helper
def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')

        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', (name, email, password))
            conn.commit()
            flash('Signup successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Email already exists.', 'danger')
        finally:
            conn.close()
    return render_template('signup.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password_input = request.form['password']

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user['password'], password_input):
            session['user_id'] = user['id']
            session['user_name'] = user['name']
            flash('Login successful!', 'success')
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))


@app.route('/admin', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password_input = request.form['password']

        conn = get_db_connection()
        admin = conn.execute('SELECT * FROM admins WHERE username = ?', (username,)).fetchone()
        conn.close()

        if admin and bcrypt.check_password_hash(admin['password'], password_input):
            session['admin'] = True
            flash('Admin login successful.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'danger')

    return render_template('admin_login.html')


@app.route('/admin/dashboard')
def admin_dashboard():
    if not session.get('admin'):
        flash('Admin access only.', 'danger')
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('admin_dashboard.html', users=users)


@app.route('/admin/delete/<int:user_id>')
def delete_user(user_id):
    if not session.get('admin'):
        flash('Unauthorized.', 'danger')
        return redirect(url_for('admin_login'))

    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

    flash('User deleted successfully.', 'success')
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/logout')
def admin_logout():
    session.pop('admin', None)
    flash('Admin logged out.', 'info')
    return redirect(url_for('admin_login'))

from flask import g

@app.before_request
def load_logged_in_user():
    g.user = None
    if 'user_id' in session:
        conn = get_db_connection()
        g.user = conn.execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()
        conn.close()

@app.route('/donor/register', methods=['GET', 'POST'])
def register_donor():
    if not g.user:
        flash('Please log in to register as a donor.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        blood_group = request.form['blood_group']
        phone = request.form['phone']
        city = request.form['city']

        conn = get_db_connection()
        conn.execute('INSERT INTO donors (user_id, blood_group, phone, city) VALUES (?, ?, ?, ?)',
                     (g.user['id'], blood_group, phone, city))
        conn.commit()
        conn.close()

        flash('You have been registered as a donor!', 'success')
        return redirect(url_for('home'))

    return render_template('donor_register.html')


@app.route('/request/blood', methods=['GET', 'POST'])
def request_blood():
    if not g.user:
        flash('Please log in to request blood.', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        blood_group = request.form['blood_group']
        phone = request.form['phone']
        city = request.form['city']
        reason = request.form['reason']

        conn = get_db_connection()
        conn.execute('INSERT INTO blood_requests (requester_id, blood_group, phone, city, reason) VALUES (?, ?, ?, ?, ?)',
                     (g.user['id'], blood_group, phone, city, reason))
        conn.commit()
        conn.close()

        flash('Blood request submitted successfully!', 'success')
        return redirect(url_for('match_donors', blood_group=blood_group, city=city))

    return render_template('blood_request.html')


@app.route('/donors/match')
def match_donors():
    blood_group = request.args.get('blood_group')
    city = request.args.get('city')

    conn = get_db_connection()
    donors = conn.execute('SELECT d.*, u.name, u.email FROM donors d JOIN users u ON d.user_id = u.id WHERE d.blood_group = ? AND d.city = ?', (blood_group, city)).fetchall()
    conn.close()

    return render_template('donor_match.html', donors=donors, blood_group=blood_group, city=city)

@app.route('/my-requests')
def my_requests():
    if not g.user:
        flash('Please log in to view your requests.', 'warning')
        return redirect(url_for('login'))

    conn = get_db_connection()
    requests = conn.execute(
        'SELECT * FROM blood_requests WHERE requester_id = ? ORDER BY id DESC',
        (g.user['id'],)
    ).fetchall()
    conn.close()

    return render_template('my_requests.html', requests=requests)



if __name__ == '__main__':
    app.run(debug=True)
