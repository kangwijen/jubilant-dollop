import os
import random
import string
import base64
import requests
import mysql.connector
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_from_directory, render_template_string

app = Flask(__name__)
app.template_folder = 'flask_templates'
UPLOAD_FOLDER = 'uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def get_db_connection():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="root",
        password="root",
        database="LKSN24",
        port=5506
    )

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute('''CREATE DATABASE IF NOT EXISTS LKSN24''')
    cursor.execute('''USE LKSN24''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255),
            password VARCHAR(255),
            role VARCHAR(255)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS comments (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            comment TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INT AUTO_INCREMENT PRIMARY KEY,
            product VARCHAR(255)
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS category (
            id INT AUTO_INCREMENT PRIMARY KEY,
            category_name VARCHAR(255)
        )
    ''')
    
    conn.commit()
    conn.close()

def generate_data():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM products")
    if len(cursor.fetchall()) > 0:
        return

    products = [
        'Apple', 'Banana', 'Cherry', 'Durian', 'Elderberry', 'Fig', 'Grape',
        'Honeydew', 'Ice Cream', 'Jujube', 'Kiwi', 'Lemon', 'Mango', 'Nectarine',
        'Orange', 'Papaya', 'Quince', 'Raspberry', 'Strawberry', 'Tomato', 'Ugli Fruit',
        'Vanilla', 'Watermelon', 'Xylocarp', 'Yam', 'Zucchini'
    ]
    for product in products:
        cursor.execute("INSERT INTO products (product) VALUES (%s)", (product,))
    conn.commit()

    users = [
        ('anonymous', 'password0'),
        ('John Doe', 'password1'),
        ('Jane Doe', 'password2'),
        ('Alice', 'password3'),
        ('Bob', 'password4'),
        ('Charlie', 'password5'),
        ('David', 'password6'),
        ('Eve', 'password7'),
        ('Frank', 'password8'),
        ('Grace', 'password9')
    ]
    user_ids = []
    for username, password in users:
        cursor.execute("INSERT INTO users (username, password) VALUES (%s, %s)", (username, password))
        user_ids.append(cursor.lastrowid)
    conn.commit()

    comments = [
        (user_ids[1], 'This is a comment 1'),
        (user_ids[2], 'This is another comment 2'),
        (user_ids[3], 'This is a comment 3'),
        (user_ids[4], 'This is another comment 4'),
        (user_ids[5], 'This is a comment 5'),
        (user_ids[6], 'This is another comment 6'),
        (user_ids[7], 'This is a comment 7'),
        (user_ids[8], 'This is another comment 8'),
        (user_ids[9], 'This is a comment 9')
    ]
    for user_id, comment in comments:
        cursor.execute("INSERT INTO comments (user_id, comment) VALUES (%s, %s)", (user_id, comment))
    conn.commit()

    cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
    conn.commit()

    conn.close()

@app.route('/')
@app.route('/index')
@app.route('/index/')
@app.route('/home')
@app.route('/home/')
def index():
    return render_template('index.html')

@app.route('/xss')
@app.route('/xss/')
@app.route('/xss/<xss_type>', methods=['GET', 'POST'])
def xss(xss_type=None):
    blacklisted_keywords = ['script', 'onload', 'onerror', 'alert', 'prompt', 'confirm', 'eval', 'fetch']

    if xss_type == 'reflected':
        if request.method == 'POST':
            search = request.form['search']
            if any(word in search for word in blacklisted_keywords):
                return render_template_string('You cannot run JavaScript in your search')

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM products WHERE product LIKE %s", ('%' + search + '%',))
            products = cursor.fetchall()
            conn.close()

            return render_template('xss_reflected.html', search=search, products=products)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        conn.close()
        return render_template('xss_reflected.html', products=products)

    if xss_type == 'stored':
        if request.method == 'POST':
            comment = request.form['comment']
            if any(word in comment.lower() for word in blacklisted_keywords):
                return render_template_string('You cannot run JavaScript in your comment')

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT id FROM users WHERE username = 'anonymous'")
            anonymous_user_id = cursor.fetchone()[0]

            cursor.execute("INSERT INTO comments (user_id, comment) VALUES (%s, %s)", (anonymous_user_id, comment))
            conn.commit()
            conn.close()
            return redirect(url_for('xss', xss_type='stored'))

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT users.username, comments.comment FROM comments JOIN users ON comments.user_id = users.id")
        comments = cursor.fetchall()
        conn.close()
        return render_template('xss_stored.html', comments=comments)

    if xss_type == 'dom':
        if request.method == 'POST':
            search = request.form['search']
            if any(word in search for word in blacklisted_keywords):
                return render_template_string('You cannot run JavaScript in your search')

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM products WHERE product LIKE %s", ('%' + search + '%',))
            products = cursor.fetchall()
            conn.close()

            return jsonify(products)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        conn.close()
        return render_template('xss_dom.html', products=products)

    if xss_type is None or xss_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/sql')
@app.route('/sql/')
@app.route('/sql/<sql_type>', methods=['GET', 'POST'])
def sql(sql_type=None):
    if sql_type == 'inband':
        if request.method == 'POST':
            search = request.form['search']

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SET GLOBAL local_infile = 0")
            cursor.execute(f"SELECT * FROM products WHERE product LIKE '%{search}%'")
            products = cursor.fetchall()
            conn.close()

            return render_template('sql_inband.html', search=search, products=products)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM products")
        products = cursor.fetchall()
        conn.close()

        return render_template('sql_inband.html', products=products)

    if sql_type == 'blind':
        if request.method == 'POST':
            search = request.form['search']

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SET GLOBAL local_infile = 0")
            cursor.execute(f"SELECT * FROM products WHERE product LIKE '%{search}%'")
            products = cursor.fetchall()
            conn.close()

            return render_template('sql_blind.html', search=search, products=products)

        return render_template('sql_blind.html')

    if sql_type == 'oob':
        if request.method == 'POST':
            search = request.form['search']

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SET GLOBAL local_infile = 1")
            try:
                cursor.execute(f"SELECT * FROM products WHERE product LIKE '%{search}%'")
                products = cursor.fetchall()
            except:
                products = []
            conn.close()

            return render_template('sql_oob.html', search=search, products=products)

        return render_template('sql_oob.html')

    if sql_type is None or sql_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/bac')
@app.route('/bac/')
@app.route('/bac/<bac_type>', methods=['GET', 'POST'])
def bac(bac_type=None):
    if bac_type == 'horizontal':
        user_id = request.args.get('user')
        
        if user_id == '' or user_id is None:
            return redirect(url_for('bac', bac_type='horizontal', user='1'))

        if user_id is not None:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
            user = cursor.fetchall()
            conn.close()

            return render_template('bac_horizontal.html', user=user)

    if bac_type == 'vertical':
        request_referer = request.headers.get('Referer')
        if request_referer is None:
            request_referer = '0.0.0.0'

        if '127.0.0.1' in request_referer:
            flag = open('flag.txt', 'r').read()
            user = [(1, 'admin', 'admin')]

            return render_template('bac_vertical.html', user=user, flag=flag)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE id = 1")
        user = cursor.fetchall()
        conn.close()

        return render_template('bac_vertical.html', user=user)

    if bac_type is None or bac_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

def generate_otp():
    otp = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
    return otp

random_page = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))

otp_table = {}

@app.route('/blv')
@app.route('/blv/')
@app.route('/blv/<blv_request>', methods=['GET', 'POST'])
def blv(blv_request=None):
    if blv_request == 'login':
        if request.method == 'POST':
            username = request.form['username']

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchall()
            conn.close()

            if len(user) > 0:
                otp = generate_otp()
                response = redirect(url_for('blv', blv_request='otp'))
                cookie = base64.b64encode(username.encode() + b':' + otp.encode()).decode()
                response.set_cookie('user', cookie)
                otp_table[cookie] = otp
                return response

            return render_template_string('Invalid username or password')

        return render_template('blv.html')

    if blv_request == 'otp':
        if request.method == 'POST':
            cookie = request.cookies.get('user')
            otp = request.json['otp']

            if cookie is None or cookie == '' or cookie not in otp_table:
                return jsonify(success=False, message='Invalid OTP')

            if otp == otp_table[cookie]:
                return jsonify(success=True)

            return jsonify(success=False, message='Invalid OTP')

        return render_template('blv_otp.html', page=random_page)

    if blv_request == random_page:
        cookie = request.cookies.get('user')
        if cookie is None or cookie == '' or cookie not in otp_table:
            return redirect(url_for('blv', blv_request='login'))

        if 'admin' in base64.b64decode(cookie).decode():
            return render_template_string(open('flag.txt', 'r').read())
        else:
            return render_template_string('You are not admin')

        return redirect(url_for('blv', blv_request='login'))

    if blv_request is None or blv_request == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

random_page2 = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))
random_cookie = ''.join(random.choices(string.ascii_lowercase + string.digits, k=12))

@app.route('/mass')
@app.route('/mass/')
@app.route('/mass/<mass_type>', methods=['GET', 'POST'])
def mass(mass_type=None):
    if mass_type == 'register':
        if request.method == 'POST':
            data = request.json
            username = data['username']
            password = data['password']
            role = data['role'] if 'role' in data else 'user'

            print(username, password, role)

            conn = get_db_connection()
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
            user = cursor.fetchall()
            if len(user) > 0:
                conn.close()
                return jsonify(success=False, message='Username already exists')

            cursor.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s)", (username, password, role))
            conn.commit()
            conn.close()

            return jsonify(success=True, message='User registered successfully')

        return render_template('mass_register.html')

    if mass_type == 'login':
        if request.method == 'POST':
            data = request.json
            username = data['username']
            password = data['password']

            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
            user = cursor.fetchall()
            conn.close()

            if len(user) > 0:
                if user[0][3] == 'admin':
                    response = jsonify(success=True, message='You are admin')
                    response.set_cookie('user', random_cookie)
                    return response

                return jsonify(success=False, message='You are not admin')

            return jsonify(success=False, message='Invalid username or password')

        return render_template('mass_login.html', page=random_page2)

    if mass_type == random_page2:
        cookie = request.cookies.get('user')
        if cookie is None or cookie == '' or cookie != random_cookie:
            return redirect(url_for('mass', mass_type='login'))

        if cookie == random_cookie:
            return render_template_string(open('flag.txt', 'r').read())

        return redirect(url_for('mass', mass_type='register'))

    if mass_type is None or mass_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/fi')
@app.route('/fi/')
@app.route('/fi/<fi_type>', methods=['GET', 'POST'])
def fi(fi_type=None):
    if fi_type == 'local':
        if request.method == 'POST':
            filename = request.json['filename']
            filepath = os.path.join('assets', filename)
            if os.path.exists(filepath):
                with open(filepath, 'rb') as file:
                    file_data = file.read()
                encoded_data = base64.b64encode(file_data).decode('utf-8')
                return jsonify(success=True, data=encoded_data)
            else:
                return jsonify(success=False, error='File not found')
        return render_template('fi_local.html')

    if fi_type == 'remote':
        if request.method == 'POST':
            filename = request.json['filename']
            response = requests.get(f'{filename}')
            if response.status_code == 200:
                encoded_data = base64.b64encode(response.content).decode('utf-8')
                return jsonify(success=True, data=encoded_data)
            else:
                return jsonify(success=False, error='File not found')
        return render_template('fi_remote.html')

    if fi_type is None or fi_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/rce')
@app.route('/rce/')
@app.route('/rce/<rce_type>', methods=['GET', 'POST'])
def rce(rce_type):
    if rce_type == 'command':
        if request.method == 'POST':
            data = request.json
            ip = data['ip']
            if ip is None or ip == '':
                return jsonify(success=False, message='No command provided')
            
            command_output = os.popen(f"tracert {ip}").read()
            return jsonify(success=True, output=command_output)

        return render_template('rce.html')

    if rce_type is None or rce_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/ssrf')
@app.route('/ssrf/')
@app.route('/ssrf/<ssrf_type>', methods=['GET', 'POST'])
def ssrf(ssrf_type):
    if ssrf_type == 'request':
        if request.method == 'POST':
            url = request.json['url']
            if url is None or url == '':
                return jsonify(success=False, message='No URL provided')

            try:
                headers = {'Host': '127.0.0.1'}
                response = requests.get(url, headers=headers)
                return jsonify(success=True, data=response.text)
            except Exception as e:
                return jsonify(success=False, message=str(e))

        return render_template('ssrf_request.html')

    if ssrf_type is None or ssrf_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/ssti')
@app.route('/ssti/')
@app.route('/ssti/<ssti_type>', methods=['GET', 'POST'])
def ssti(ssti_type):
    if ssti_type == 'render':
        if request.method == 'POST':
            template = request.json['text']
            if template is None or template == '':
                return jsonify(success=False, message='No template provided')

            return render_template_string(template)

        return render_template('ssti_render.html')

    if ssti_type is None or ssti_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

@app.route('/deserialization')
@app.route('/deserialization/')
@app.route('/deserialization/<deserialization_type>', methods=['GET', 'POST'])
def deserialization(deserialization_type):
    if deserialization_type == 'pickle':
        if request.method == 'POST':
            data = request.json['data']
            if data is None or data == '':
                return jsonify(success=False, message='No data provided')

            try:
                import pickle
                data = base64.b64decode(data)
                data = pickle.loads(data)
                return jsonify(success=True, data=data)
            except Exception as e:
                return jsonify(success=False, message=str(e))

        return render_template('deserialization_pickle.html')

    if deserialization_type is None or deserialization_type == '':
        return redirect(url_for('index'))

    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()
    generate_data()
    app.run(debug=True, host="0.0.0.0", port=5000)
