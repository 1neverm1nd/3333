from flask import Flask, render_template, request, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from cryptography.fernet import Fernet

import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SECRET_KEY'] = 'your_secret_key'
db = SQLAlchemy(app)

# Модель пользователя
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

# Модель поста
class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    encrypted_file = db.Column(db.String(200), nullable=False)  # Путь к зашифрованному файлу
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# Создание базы данных
with app.app_context():
    db.create_all()

# Маршрут для регистрации
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        # Изменяем метод хеширования на 'pbkdf2:sha256'
        password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

# Маршрут для авторизации
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('upload_file'))
        else:
            return "Неверные данные для входа"
    return render_template('login.html')

# Маршрут для загрузки и шифрования файлов
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        return redirect(url_for('login'))  # Ограничение доступа

    if request.method == 'POST':
        title = request.form['title']
        content = request.form['content']
        file = request.files['file']

        # Шифрование файла
        key = Fernet.generate_key()
        fernet = Fernet(key)
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)

        with open(file_path, 'rb') as original_file:
            original_data = original_file.read()

        encrypted_data = fernet.encrypt(original_data)
        encrypted_file_path = f'encrypted_{file.filename}'

        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        # Сохранение поста в базе данных
        new_post = Post(title=title, content=content, encrypted_file=encrypted_file_path, user_id=session['user_id'])
        db.session.add(new_post)
        db.session.commit()

        return f"Файл зашифрован и сохранен. Ваш ключ: {key.decode()}"

    return render_template('upload.html')

# Маршрут для просмотра всех постов
@app.route('/posts')
def posts():
    all_posts = Post.query.all()
    return render_template('posts.html', posts=all_posts)

# Маршрут для расшифровки файла
@app.route('/decrypt/<int:post_id>', methods=['GET', 'POST'])
def decrypt_file(post_id):
    post = Post.query.get(post_id)
    if request.method == 'POST':
        key = request.form['key']
        try:
            fernet = Fernet(key.encode())
            with open(post.encrypted_file, 'rb') as encrypted_file:
                encrypted_data = encrypted_file.read()

            decrypted_data = fernet.decrypt(encrypted_data)

            # Сохранение расшифрованного файла
            decrypted_file_path = f'decrypted_{os.path.basename(post.encrypted_file)}'
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)

            return f"Файл расшифрован и сохранен как {decrypted_file_path}"
        except Exception as e:
            return f"Ошибка расшифровки: {str(e)}"

    return render_template('decrypt.html', post=post)

# Маршрут для выхода из системы
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))
@app.route('/')
def home():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)
