# Импорт необходимых модулей
import os  # Для работы с файловой системой
import uuid  # Для генерации уникальных идентификаторов
from datetime import datetime, timedelta  # Для работы с датой и временем
from email.policy import default

from flask import Flask, render_template, redirect, url_for, flash, abort, request, send_from_directory  # Основные компоненты Flask
from flask_sqlalchemy import SQLAlchemy  # ORM для работы с базой данных
from sqlalchemy.exc import IntegrityError  # Ошибка целостности БД
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user  # Аутентификация пользователей
from werkzeug.security import generate_password_hash, check_password_hash  # Хеширование паролей
from werkzeug.utils import secure_filename  # Безопасная обработка имён файлов
from flask_wtf import FlaskForm  # Базовый класс для форм
from wtforms import StringField, PasswordField, SubmitField, TextAreaField, BooleanField, FileField  # Поля форм
from wtforms.validators import DataRequired, Length, Email  # Валидаторы для полей форм
from flask_wtf.csrf import CSRFProtect  # Защита от CSRF-атак

# Создание экземпляра приложения Flask
app = Flask(__name__)
# Конфигурация приложения
app.config['SECRET_KEY'] = 'ADMIN'  # Секретный ключ для подписи сессий
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///filehost.db'  # Путь к SQLite базе данных
app.config['UPLOAD_FOLDER'] = 'uploads'  # Папка для загружаемых файлов
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Максимальный размер файла (16MB)
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'zip', 'doc', 'docx'}  # Разрешенные расширения файлов
app.config['LINK_EXPIRE_HOURS'] = 12  # Время жизни ссылки в часах
csrf = CSRFProtect(app)  # Инициализация CSRF-защиты

# Инициализация расширений
db = SQLAlchemy(app)  # Подключение SQLAlchemy
login_manager = LoginManager(app)  # Менеджер аутентификации
login_manager.login_view = 'login'  # Страница входа

# Создание папки для загрузок, если её нет
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Функция проверки разрешенных расширений файлов
def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Форма регистрации пользователя
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(3, 64)])  # Поле имени пользователя
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])  # Поле email
    password = PasswordField('Password', validators=[DataRequired()])  # Поле пароля
    submit = SubmitField('Register')  # Кнопка отправки формы

# Форма входа пользователя
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])  # Поле имени пользователя
    password = PasswordField('Password', validators=[DataRequired()])  # Поле пароля
    remember_me = BooleanField('Remember Me')  # Чекбокс "Запомнить меня"
    submit = SubmitField('Login')  # Кнопка отправки формы

# Форма редактирования профиля
class ProfileForm(FlaskForm):
    full_name = StringField('Full Name', validators=[Length(0, 100)])  # Поле полного имени
    avatar = FileField('Avatar')  # Поле для загрузки аватара
    submit = SubmitField('Update Profile')  # Кнопка обновления профиля

# Форма загрузки файла
class UploadFileForm(FlaskForm):
    file = FileField('File', validators=[DataRequired()])  # Поле для выбора файла
    description = TextAreaField('Description')  # Поле описания файла
    submit = SubmitField('Upload')  # Кнопка загрузки

# Форма редактирования информации о файле
class EditFileForm(FlaskForm):
    description = TextAreaField('Description')  # Поле описания файла
    submit = SubmitField('Save Changes')  # Кнопка сохранения изменений

# Форма создания ссылки для скачивания
class CreateLinkForm(FlaskForm):
    submit = SubmitField('Generate Download Link')  # Кнопка генерации ссылки

# Модель пользователя
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)  # ID пользователя
    username = db.Column(db.String(64), unique=True, index=True)  # Имя пользователя
    email = db.Column(db.String(120), unique=True, index=True, nullable=False)  # Email
    password_hash = db.Column(db.String(128))  # Хеш пароля
    full_name = db.Column(db.String(100))  # Полное имя
    avatar = db.Column(db.String(200))  # Путь к аватару
    is_admin = db.Column(db.Boolean, default=False)  # Флаг администратора
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Дата создания
    files = db.relationship('File', backref='owner', lazy='dynamic')  # Связь с файлами пользователя

    # Метод установки пароля
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    # Метод проверки пароля
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Метод получения URL аватара
    def get_avatar_url(self):
        if self.avatar:
            return url_for('static', filename=f'avatars/{self.avatar}')
        return 'https://www.gravatar.com/avatar/default'

# Модель файла
class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    original_name = db.Column(db.String(256))
    storage_name = db.Column(db.String(64), unique=True)
    description = db.Column(db.Text)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    deleted = db.Column(db.DateTime, nullable=True, default=None)
    size = db.Column(db.Integer)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    download_links = db.relationship('DownloadLink', backref='file', lazy='dynamic')

    # Метод получения URL для скачивания
    def get_download_url(self):
        return url_for('download_file', file_id=self.id)

    # Метод получения размера файла в MB
    def get_size_mb(self):
        return round(self.size / (1024 * 1024), 2) if self.size else 0

# Модель ссылки для скачивания
class DownloadLink(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    token = db.Column(db.String(64), unique=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime)
    download_count = db.Column(db.Integer, default=0)
    is_active = db.Column(db.Boolean, default=True)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'))

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Установка времени истечения, если не задано
        if not self.expires_at:
            self.expires_at = datetime.utcnow() + timedelta(hours=app.config['LINK_EXPIRE_HOURS'])

    # Проверка истекла ли ссылка
    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    # Обновление статуса ссылки
    def update_status(self):
        if self.is_expired():
            self.is_active = False
            return False
        return True

    # Получение URL для скачивания по ссылке
    def get_download_url(self):
        return url_for('download_via_link', token=self.token)

    # Деактивация ссылки
    def deactivate(self):
        self.is_active = False
        db.session.commit()

# Загрузчик пользователя для Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Маршрут главной страницы
@app.route('/')
def index():
    return render_template('index.html')  # Рендеринг шаблона index.html

# Маршрут регистрации пользователя
@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:  # Если пользователь уже авторизован
        return redirect(url_for('index'))  # Перенаправляем на главную

    form = RegistrationForm()
    if request.method == "POST" and form.validate_on_submit():  # Если форма отправлена и валидна
        try:
            # Проверка уникальности имени пользователя
            if User.query.filter_by(username=form.username.data).first():
                flash('Username already exists')
                return redirect(url_for('register'))

            # Проверка уникальности email
            if User.query.filter_by(email=form.email.data).first():
                flash('Email address already registered')
                return redirect(url_for('register'))

            # Проверка, является ли пользователь первым (админом)
            is_first_user = User.query.count() == 0

            # Создание нового пользователя
            user = User(
                username=form.username.data,
                email=form.email.data,
                is_admin=is_first_user  # Первый пользователь - админ
            )
            user.set_password(form.password.data)  # Установка пароля
            db.session.add(user)  # Добавление в сессию
            db.session.commit()  # Сохранение в БД

            if is_first_user:
                flash('Admin account created successfully!')
            else:
                flash('Registration successful! Please log in.')

            return redirect(url_for('login'))

        except IntegrityError as e:  # Обработка ошибок БД
            db.session.rollback()
            flash('An error occurred during registration. Please try again.')
            app.logger.error(f'Database error: {str(e)}')
            return redirect(url_for('register'))

    return render_template('auth/register.html', form=form)  # Рендеринг формы регистрации

# Маршрут входа пользователя
@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:  # Если уже авторизован
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():  # Если форма отправлена и валидна
        user = User.query.filter_by(username=form.username.data).first()  # Поиск пользователя
        if user and user.check_password(form.password.data):  # Проверка пароля
            login_user(user, remember=form.remember_me.data)  # Вход пользователя
            next_page = request.args.get('next')  # Получение страницы для перенаправления
            return redirect(next_page) if next_page else redirect(url_for('index'))
        flash('Invalid username or password')  # Сообщение об ошибке

    return render_template('auth/login.html', form=form)  # Рендеринг формы входа

# Маршрут выхода пользователя
@app.route('/logout')
@login_required  # Только для авторизованных
def logout():
    logout_user()  # Выход пользователя
    return redirect(url_for('index'))  # Перенаправление на главную

# Маршрут профиля пользователя
@app.route('/profile', methods=['GET', 'POST'])
@login_required  # Только для авторизованных
def profile():
    form = ProfileForm()
    if form.validate_on_submit():  # Если форма отправлена и валидна
        current_user.full_name = form.full_name.data  # Обновление имени

        if form.avatar.data:  # Если загружен новый аватар
            filename = secure_filename(form.avatar.data.filename)  # Безопасное имя файла
            unique_filename = f"{uuid.uuid4().hex}_{filename}"  # Генерация уникального имени
            avatar_path = os.path.join(app.root_path, 'static', 'avatars', unique_filename)  # Путь сохранения
            os.makedirs(os.path.dirname(avatar_path), exist_ok=True)  # Создание папки если нужно
            form.avatar.data.save(avatar_path)  # Сохранение файла

            # Удаление старого аватара если есть
            if current_user.avatar:
                old_avatar = os.path.join('static', 'avatars', current_user.avatar)
                if os.path.exists(old_avatar):
                    os.remove(old_avatar)

            current_user.avatar = unique_filename  # Обновление аватара в БД

        db.session.commit()  # Сохранение изменений
        flash('Your profile has been updated!')
        return redirect(url_for('profile'))
    elif request.method == 'GET':  # При GET-запросе заполняем форму текущими данными
        form.full_name.data = current_user.full_name

    return render_template('profile.html', form=form)  # Рендеринг шаблона профиля

# Маршрут списка файлов пользователя
@app.route('/files')
@login_required
def user_files():
    files = current_user.files.order_by(File.upload_date.desc()).all()  # Получение файлов пользователя
    return render_template('files/files.html', files=files)  # Рендеринг шаблона

# Маршрут загрузки файла
@app.route('/files/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = UploadFileForm()
    if form.validate_on_submit():  # Если форма отправлена и валидна
        file = form.file.data
        if not (file and allowed_file(file.filename)):  # Проверка расширения файла
            flash('Your file not allowed!')
            return render_template('files/upload.html', form=form)  # Рендеринг формы загрузки

        filename = secure_filename(file.filename)  # Безопасное имя файла
        unique_filename = f"{uuid.uuid4().hex}_{filename}"  # Генерация уникального имени
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)  # Путь сохранения
        file.save(file_path)  # Сохранение файла

        # Создание записи о файле в БД
        new_file = File(
            original_name=filename,
            storage_name=unique_filename,
            description=form.description.data,
            size=os.path.getsize(file_path),  # Получение размера файла
            owner=current_user
        )
        db.session.add(new_file)  # Добавление в сессию
        db.session.commit()  # Сохранение в БД

        flash('File uploaded successfully!')
        return redirect(url_for('user_files'))

    return render_template('files/upload.html', form=form)  # Рендеринг формы загрузки

# Маршрут деталей файла
@app.route('/files/<int:file_id>', methods=['GET', 'POST'])
@login_required
def file_details(file_id):
    file = File.query.get_or_404(file_id)  # Получение файла или 404
    if file.owner != current_user and not current_user.is_admin:  # Проверка прав доступа
        abort(403)

    form = EditFileForm()
    if form.validate_on_submit():  # Если форма отправлена и валидна
        file.description = form.description.data  # Обновление описания
        db.session.commit()  # Сохранение в БД
        flash('File description updated.')
        return redirect(url_for('file_details', file_id=file.id))
    elif request.method == 'GET':  # При GET-запросе заполняем форму
        form.description.data = file.description

    # Получение всех ссылок для файла
    links = file.download_links.order_by(DownloadLink.created_at.desc()).all()
    link_form = CreateLinkForm()  # Форма создания ссылки

    return render_template('files/file_details.html',
                           file=file,
                           form=form,
                           links=links,
                           link_form=link_form)

# Маршрут скачивания файла
@app.route('/files/<int:file_id>/download')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)  # Получение файла или 404
    if file.owner != current_user and not current_user.is_admin:  # Проверка прав доступа
        abort(403)

    # Отправка файла пользователю
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               file.storage_name,
                               as_attachment=True,
                               download_name=file.original_name)

# Маршрут удаления файла
@app.route('/files/<int:file_id>/delete', methods=['POST'])
@login_required
def delete_file(file_id):
    file = File.query.get_or_404(file_id)  # Получение файла или 404
    if file.owner != current_user:  # Проверка прав доступа
        abort(403)

    # Удаление файла с диска
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.storage_name)
    if os.path.exists(file_path):
        os.remove(file_path)

    # Удаление записи о файле из БД
    db.session.delete(file)
    db.session.commit()

    flash('File deleted successfully.')
    return redirect(url_for('user_files'))

# Маршрут создания ссылки для скачивания
@app.route('/files/<int:file_id>/links/create', methods=['POST'])
@login_required
def create_download_link(file_id):
    file = File.query.get_or_404(file_id)  # Получение файла или 404
    if file.owner != current_user:  # Проверка прав доступа
        abort(403)

    # Создание новой ссылки
    new_link = DownloadLink(token=uuid.uuid4().hex, file=file)
    db.session.add(new_link)
    db.session.commit()

    # Генерация полного URL для новой ссылки
    full_url = url_for('download_via_link', token=new_link.token, _external=True)
    flash(f'Создана новая ссылка: {full_url}', 'success')
    return redirect(url_for('file_details', file_id=file.id))

# Маршрут скачивания по ссылке
@app.route('/download/<token>')
def download_via_link(token):
    link = DownloadLink.query.filter_by(token=token).first_or_404()  # Поиск ссылки или 404

    # Проверка активности ссылки
    if not link.is_active or link.is_expired():
        if link.is_active:
            link.is_active = False
            db.session.commit()
        abort(410, description="Link expired or deactivated")  # Ссылка недействительна

    link.download_count += 1  # Увеличение счетчика скачиваний
    db.session.commit()

    # Отправка файла
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        link.file.storage_name,
        as_attachment=True,
        download_name=link.file.original_name
    )

# Маршрут админки - список пользователей
@app.route('/admin/users')
@login_required
def admin_users():
    if not current_user.is_admin:  # Проверка прав администратора
        abort(403)

    users = User.query.order_by(User.created_at.desc()).all()  # Получение всех пользователей
    return render_template('admin/users.html', users=users)  # Рендеринг шаблона

# Маршрут админки - список файлов
@app.route('/admin/files')
@login_required
def admin_files():
    if not current_user.is_admin:  # Проверка прав администратора
        abort(403)

    files = File.query.order_by(File.upload_date.desc()).all()  # Получение всех файлов
    return render_template('admin/files.html', files=files)  # Рендеринг шаблона

# Маршрут админки - список ссылок
@app.route('/admin/links')
@login_required
def admin_links():
    if not current_user.is_admin:  # Проверка прав администратора
        abort(403)

    links = DownloadLink.query.order_by(DownloadLink.created_at.desc()).all()  # Получение всех ссылок
    return render_template('admin/links.html', links=links)  # Рендеринг шаблона

# Маршрут изменения прав администратора
@app.route('/admin/users/<int:user_id>/toggle_admin', methods=['POST'])
@login_required
def toggle_admin(user_id):
    if not current_user.is_admin:  # Проверка прав администратора
        abort(403)

    user = User.query.get_or_404(user_id)  # Получение пользователя или 404

    # Запрет изменения своих прав
    if user == current_user:
        flash('You cannot change your own admin status', 'danger')
        return redirect(url_for('admin_users'))

    user.is_admin = not user.is_admin  # Изменение прав
    db.session.commit()  # Сохранение в БД

    action = "granted" if user.is_admin else "revoked"
    flash(f'Admin rights {action} for {user.username}')
    return redirect(url_for('admin_users'))

# Маршрут удаления ссылки
@app.route('/links/<int:link_id>/delete', methods=['POST'])
@login_required
def delete_link(link_id):
    link = DownloadLink.query.get_or_404(link_id)  # Получение ссылки или 404
    file = link.file

    # Проверка прав: владелец файла или администратор
    if file.owner != current_user and not current_user.is_admin:
        abort(403)

    db.session.delete(link)  # Удаление ссылки
    db.session.commit()
    flash('Ссылка удалена', 'success')
    return redirect(url_for('file_details', file_id=file.id))

# Маршрут деактивации ссылки
@app.route('/links/<int:link_id>/deactivate', methods=['POST'])
@login_required
def deactivate_link(link_id):
    link = DownloadLink.query.get_or_404(link_id)  # Получение ссылки или 404
    file = link.file

    # Проверка прав: владелец файла или администратор
    if file.owner != current_user and not current_user.is_admin:
        abort(403)

    link.deactivate()  # Деактивация ссылки
    flash('Ссылка деактивирована', 'success')
    return redirect(url_for('file_details', file_id=file.id))

# Точка входа в приложение
if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Создание таблиц в БД

        if User.query.count() == 0:
            admin = User(
                username='admin',
                email='admin@example.com',
                is_admin=True
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()


    app.run(debug=True)  # Запуск приложения в режиме отладки