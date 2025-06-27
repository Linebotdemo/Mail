import os
import csv
import io
import json
from datetime import date, datetime
from flask import Flask, jsonify, session, request, render_template, redirect, url_for, abort, flash, send_from_directory, current_app, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm, CSRFProtect
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import InternalServerError
from jinja2 import Template
from flask_wtf.csrf import validate_csrf, CSRFError
from functools import wraps
import sqlite3
import logging
import shortuuid
import secrets
from urllib.parse import urlparse, parse_qs
from bs4 import BeautifulSoup
import re

# Flask アプリケーションの初期化
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(16))
csrf = CSRFProtect(app)
app.config['WTF_CSRF_ENABLED'] = True  # CSRFを有効化（必要に応じてエンドポイントで無効化）

# ログ設定
logging.basicConfig(
    filename='app.log',
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] (%(pathname)s:%(lineno)d) %(message)s'
)
logger = logging.getLogger(__name__)

# データベース設定
DATABASE = 'database.db'

def get_db():
    try:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        logging.info(f'✅ Database connection established: {DATABASE}')
        return db
    except sqlite3.Error as e:
        logging.error(f'❌ Database connection failed: {e}')
        raise

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    app.logger.info('✅ Database connection established: database.db')
    return conn

def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        try:
            # 1. organizations テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS organizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL
                )
            ''')

            # 2. users テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'employee',
                    employee_id INTEGER,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 3. employees テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS employees (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    department TEXT,
                    role TEXT,
                    phone TEXT,
                    address TEXT,
                    website TEXT,
                    linkedin TEXT,
                    password TEXT,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 4. templates テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    html_content TEXT,
                    text_content TEXT,
                    banner_url TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    campaign_id INTEGER,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (campaign_id) REFERENCES campaigns(id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 5. campaigns テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    template_ids TEXT NOT NULL,
                    department TEXT,
                    start_date TIMESTAMP NOT NULL,
                    end_date TIMESTAMP NOT NULL,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 6. signature_history テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signature_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER,
                    template_id INTEGER,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (employee_id) REFERENCES employees(id),
                    FOREIGN KEY (template_id) REFERENCES templates(id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 7. tracking テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    track_id TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    template_id INTEGER,
                    employee_id INTEGER,
                    clicks INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (template_id) REFERENCES templates(id),
                    FOREIGN KEY (employee_id) REFERENCES employees(id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 8. signature_assignments テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signature_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER NOT NULL,
                    template_id INTEGER NOT NULL,
                    assigned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    applied_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (employee_id) REFERENCES employees(id),
                    FOREIGN KEY (template_id) REFERENCES templates(id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 9. analytics テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analytics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    track_id TEXT NOT NULL,
                    template_id INTEGER,
                    employee_id INTEGER,
                    department TEXT,
                    clicked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    ip TEXT,
                    user_agent TEXT,
                    created_at TEXT,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (template_id) REFERENCES templates(id),
                    FOREIGN KEY (employee_id) REFERENCES employees(id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 10. signature_templates テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signature_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER NOT NULL,
                    html TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (employee_id) REFERENCES employees(id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # 11. tracking_links テーブル
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    template_id INTEGER NOT NULL,
                    placeholder TEXT NOT NULL,
                    label TEXT,
                    original_url TEXT NOT NULL,
                    track_id TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    organization_id INTEGER NOT NULL,
                    FOREIGN KEY (template_id) REFERENCES templates(id),
                    FOREIGN KEY (organization_id) REFERENCES organizations(id)
                )
            ''')

            # organization_id カラムの存在確認と追加
            for table in ['users', 'employees', 'templates', 'campaigns', 'signature_history',
                          'tracking', 'signature_assignments', 'analytics', 'signature_templates',
                          'tracking_links']:
                cursor.execute(f"PRAGMA table_info({table})")
                columns = [col[1] for col in cursor.fetchall()]
                if 'organization_id' not in columns:
                    cursor.execute(f"ALTER TABLE {table} ADD COLUMN organization_id INTEGER")
                    logging.info(f'✅ Added organization_id to {table}')
                else:
                    logging.info(f'✅ {table} already has organization_id column')

            db.commit()
            logging.info('✅ Database tables created successfully')
        except sqlite3.Error as e:
            db.rollback()
            logging.error(f'❌ Database initialization failed: {e}')
            raise
        finally:
            db.close()

# ログインフォームクラス
class LoginForm(FlaskForm):
    email = StringField('メールアドレス', validators=[DataRequired()])
    password = PasswordField('パスワード', validators=[DataRequired()])
    submit = SubmitField('ログイン')

# ユーザーモデル
class User(UserMixin):
    def __init__(self, id, email, role, employee_id=None, department=None, organization_id=None):
        self.id = id
        self.email = email
        self.role = role
        self.employee_id = employee_id
        self.department = department
        self.organization_id = organization_id

    def get_id(self):
        return str(self.id)

# Flask-Login 設定
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'

@login_manager.user_loader
def load_user(user_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            logging.info(f'✅ User loaded: {user["email"]}')
            employee_id = user['employee_id'] if 'employee_id' in user.keys() else None
            organization_id = user['organization_id'] if 'organization_id' in user.keys() else None
            return User(user['id'], user['email'], user['role'], employee_id, organization_id=organization_id)
        logging.warning(f'⚠️ User not found: id={user_id}')
        return None
    except sqlite3.Error as e:
        logging.error(f'❌ User load failed: {e}')
        return None
    finally:
        db.close()

# カスタムデコレータ
def employee_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'employee':
            return jsonify({'success': False, 'message': '社員権限が必要です。'}), 403
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            logging.warning(f'⚠️ Unauthorized access attempt: {request.path}')
            flash('管理者権限が必要です。', 'danger')
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function

def org_scoped_view(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'ログインが必要です'}), 401
        return f(*args, **kwargs)
    return decorated_function

# ユーティリティ関数
def render_signature_template(template_html, variables):
    template = Template(template_html)
    return template.render(**variables)

def replace_links_with_tracking(html, employee_id, template_id):
    soup = BeautifulSoup(html, "html.parser")
    db = get_db()
    cursor = db.cursor()
    try:
        for a in soup.find_all("a", href=True):
            original_url = a["href"]
            if '/click/' in original_url:
                track_id = original_url.split('/click/')[-1]
                cursor.execute('SELECT url FROM tracking WHERE track_id = ? AND organization_id = ?', 
                              (track_id, current_user.organization_id))
                row = cursor.fetchone()
                if row:
                    original_url = row['url']
            cursor.execute('''
                SELECT * FROM tracking WHERE url = ? AND employee_id = ? AND template_id = ? AND organization_id = ?
            ''', (original_url, employee_id, template_id, current_user.organization_id))
            existing = cursor.fetchone()
            if existing:
                track_id = existing['track_id']
            else:
                track_id = shortuuid.uuid()
                cursor.execute('''
                    INSERT INTO tracking (track_id, url, employee_id, template_id, clicks, organization_id)
                    VALUES (?, ?, ?, ?, 0, ?)
                ''', (track_id, original_url, employee_id, template_id, current_user.organization_id))
                db.commit()
            a['href'] = url_for('api_track_click', track_id=track_id, _external=True)
        return str(soup)
    finally:
        db.close()

# Jinja2 カスタムフィルタ
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return value
    return value.strftime(format)

def from_json(value):
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        logging.error(f'❌ JSON decode error in from_json filter: {e}')
        return value

app.jinja_env.filters['strftime'] = format_datetime
app.jinja_env.filters['from_json'] = from_json

def get_campaigns():
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('SELECT * FROM campaigns WHERE organization_id = ?', (current_user.organization_id,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        db.close()

def get_templates():
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute('SELECT * FROM templates WHERE organization_id = ?', (current_user.organization_id,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        db.close()

def get_employees(page=1, per_page=15, filter_name=None, filter_email=None, filter_department=None, filter_role=None, search=None, sort_by=None, sort_order='asc'):
    db = get_db()
    try:
        cursor = db.cursor()
        query = 'SELECT * FROM employees WHERE organization_id = ?'
        params = [current_user.organization_id]
        if filter_name:
            query += ' AND name LIKE ?'
            params.append(f'%{filter_name}%')
        if filter_email:
            query += ' AND email LIKE ?'
            params.append(f'%{filter_email}%')
        if filter_department:
            query += ' AND department = ?'
            params.append(filter_department)
        if filter_role:
            query += ' AND role = ?'
            params.append(filter_role)
        if search:
            query += ' AND (name LIKE ? OR email LIKE ?)'
            params.extend([f'%{search}%', f'%{search}%'])
        if sort_by in ['name', 'email', 'department', 'role']:
            query += f' ORDER BY {sort_by} {sort_order.upper()}'
        count_query = query.replace('SELECT *', 'SELECT COUNT(*)')
        cursor.execute(count_query, params)
        total = cursor.fetchone()[0]
        offset = (page - 1) * per_page
        query += ' LIMIT ? OFFSET ?'
        params.extend([per_page, offset])
        cursor.execute(query, params)
        employees = [dict(row) for row in cursor.fetchall()]
        pages = (total + per_page - 1) // per_page
        logging.info(f'✅ Retrieved {len(employees)} employees, page={page}, total={total}, org_id={current_user.organization_id}')
        return {'success': True, 'employees': employees, 'total': total, 'pages': pages}
    except sqlite3.Error as e:
        logging.error(f'❌ Get employees error: {e}')
        return {'success': False, 'message': str(e)}
    finally:
        db.close()

# エラーハンドリング
@app.errorhandler(404)
def page_not_found(e):
    logging.warning(f'❌ 404 error: path={request.path}')
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    logging.error(f'❌ 500 error: {str(e)}')
    return jsonify({'error': 'Internal server error'}), 500

# ルート定義
@app.route('/')
@login_required
@org_scoped_view
def index():
    user = current_user
    employee_id = ''
    template_id = ''
    logger.debug('✅ ログインユーザー: %s (%s)', user.email, user.role)
    if user.role == 'employee':
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('SELECT id FROM employees WHERE email = ? AND organization_id = ?', 
                          (user.email, current_user.organization_id))
            row = cursor.fetchone()
            if row:
                employee_id = row['id']
                logger.debug('📌 employee_id: %s', employee_id)
                cursor.execute('''
                    SELECT template_id FROM signature_assignments
                    WHERE employee_id = ? AND organization_id = ?
                    ORDER BY assigned_at DESC
                    LIMIT 1
                ''', (employee_id, current_user.organization_id))
                assigned = cursor.fetchone()
                template_id = assigned['template_id'] if assigned else ''
                logger.debug('📌 template_id: %s', template_id)
        finally:
            db.close()
    return render_template(
        'index.html',
        user_role=user.role,
        employee_id=employee_id,
        assigned_template_id=template_id,
        initial_view='employee-portal' if user.role == 'employee' else 'admin-dashboard',
        campaigns=get_campaigns(),
        templates=get_templates()
    )

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    form = LoginForm()
    if current_user.is_authenticated:
        logging.info(f'✅ Already authenticated, redirecting: {current_user.email}')
        return redirect(url_for('index'))
    if request.method == 'POST':
        logging.info(f'📥 Login POST received: {request.form.to_dict()}')
        if not form.validate_on_submit():
            logging.warning(f'⚠️ Form validation failed: {form.errors}')
            flash('フォームの入力にエラーがあります。', 'danger')
        else:
            email = form.email.data
            password = form.password.data
            db = get_db()
            try:
                cursor = db.cursor()
                cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
                user = cursor.fetchone()
                if user and check_password_hash(user['password'], password):
                    user_obj = User(user['id'], user['email'], user['role'], user['employee_id'], organization_id=user['organization_id'])
                    login_user(user_obj)
                    session['user_id'] = user['id']
                    logging.info(f'✅ Login successful: {email}')
                    next_page = request.args.get('next', url_for('index'))
                    return redirect(next_page)
                else:
                    logging.warning(f'⚠️ Login failed: {email}')
                    flash('無効なメールアドレスまたはパスワードです。', 'danger')
            finally:
                db.close()
    logging.info('🔵 Rendering auth page')
    return render_template('auth.html', form=form)

@app.route('/api/login', methods=['POST'])
@csrf.exempt
def login():
    try:
        data = request.get_json(force=True)
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            logging.warning(f'⚠️ Missing email or password: {email}')
            return jsonify({'success': False, 'message': 'メールとパスワードを入力してください'}), 400
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
            user = cursor.fetchone()
            if user and check_password_hash(user['password'], password):
                user_obj = User(user['id'], user['email'], user['role'], user['employee_id'], organization_id=user['organization_id'])
                login_user(user_obj)
                logging.info(f'✅ Login successful: {email}')
                return jsonify({'success': True, 'redirect': '/'})
            logging.warning(f'⚠️ Login failed: {email}')
            return jsonify({'success': False, 'message': '無効な認証情報です。'}), 401
        finally:
            db.close()
    except Exception as e:
        logging.exception(f'❌ Login error: {e}')
        return jsonify({'success': False, 'message': 'サーバーエラーが発生しました。'}), 500

@app.route('/api/logout', methods=['POST'])
@login_required
@csrf.exempt
def logout():
    user_email = current_user.email
    logout_user()
    session.pop('user_id', None)
    app.logger.info(f'✅ Logout successful: {user_email}')
    return jsonify({'success': True})

@app.route('/api/session', methods=['GET'])
def session_info():
    if current_user.is_authenticated:
        user_data = {
            'id': current_user.id,
            'email': current_user.email,
            'role': current_user.role,
            'employee_id': current_user.employee_id,
            'organization_id': current_user.organization_id
        }
        logging.debug(f'🧪 /api/session user_data: {user_data}')
        return jsonify({'success': True, 'authenticated': True, 'user': user_data})
    else:
        logging.info('🔵 No active session')
        return jsonify({'success': True, 'authenticated': False})

@app.route('/api/me', methods=['GET', 'POST'])
@login_required
@org_scoped_view
def me():
    if request.method == 'GET':
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('SELECT * FROM employees WHERE id = ? AND organization_id = ?', 
                          (current_user.employee_id, current_user.organization_id))
            employee = cursor.fetchone()
            if employee:
                return jsonify({
                    'success': True,
                    'user': {
                        'id': current_user.id,
                        'name': employee['name'],
                        'email': employee['email'],
                        'department': employee['department'],
                        'role': employee['role']
                    }
                })
            return jsonify({'success': False, 'message': '社員情報が見つかりません'}), 404
        finally:
            db.close()
    else:
        data = request.form
        name = data.get('name')
        email = data.get('email')
        department = data.get('department')
        db = get_db()
        try:
            cursor = db.cursor()
            cursor.execute('''
                UPDATE employees SET name = ?, email = ?, department = ?
                WHERE id = ? AND organization_id = ?
            ''', (name, email, department, current_user.employee_id, current_user.organization_id))
            db.commit()
            return jsonify({'success': True, 'message': 'プロフィールを更新しました'})
        except sqlite3.Error as e:
            db.rollback()
            logging.error(f'❌ Update profile error: {e}')
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            db.close()

@app.route('/api/profile', methods=['GET'])
@login_required
@org_scoped_view
def get_profile():
    try:
        db = get_db()
        cursor = db.cursor()
        if current_user.employee_id:
            cursor.execute('SELECT * FROM employees WHERE id = ? AND organization_id = ?', 
                          (current_user.employee_id, current_user.organization_id))
            row = cursor.fetchone()
            if row:
                profile = dict(row)
                app.logger.info(f'✅ Profile retrieved for employee_id: {current_user.employee_id}')
                return jsonify(profile)
            else:
                app.logger.warning(f'⚠️ No employee found for employee_id: {current_user.employee_id}')
                return jsonify({'error': '社員情報が見つかりませんでした。管理者にお問い合わせください。'}), 404
        else:
            app.logger.warning(f'⚠️ No employee_id set for user: {current_user.email}, trying email lookup')
            cursor.execute('SELECT * FROM employees WHERE email = ? AND organization_id = ?', 
                          (current_user.email, current_user.organization_id))
            row = cursor.fetchone()
            if row:
                profile = dict(row)
                app.logger.info(f'✅ Profile retrieved for email: {current_user.email}')
                return jsonify(profile)
            else:
                app.logger.warning(f'⚠️ No employee found for email: {current_user.email}')
                return jsonify({'error': 'プロフィール情報が見つかりませんでした。管理者による設定が必要です。'}), 404
    except Exception as e:
        app.logger.error(f'❌ Error in /api/profile: {str(e)}')
        return jsonify({'error': 'サーバーエラーが発生しました。後でもう一度お試しください。'}), 500
    finally:
        db.close()

@app.route('/api/profile', methods=['POST'])
@login_required
@org_scoped_view
def update_profile():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    app.logger.info(f'🟡 受信データ: {data}')
    db = get_db()
    try:
        cursor = db.cursor()
        base_sql = '''
            name = ?, email = ?, department = ?, role = ?, phone = ?,
            address = ?, website = ?, linkedin = ?
        '''
        params = [
            data.get('name'), data.get('email'), data.get('department'),
            data.get('role'), data.get('phone'), data.get('address'),
            data.get('website'), data.get('linkedin')
        ]
        pw = data.get('password')
        pw_confirm = data.get('password_confirm')
        hashed_password = None
        if pw or pw_confirm:
            if not pw or not pw_confirm:
                return jsonify({'error': 'パスワードを両方入力してください。'}), 400
            if pw != pw_confirm:
                return jsonify({'error': 'パスワードが一致しません。'}), 400
            if len(pw) < 6:
                return jsonify({'error': 'パスワードは6文字以上にしてください。'}), 400
            hashed_password = generate_password_hash(pw)
            base_sql += ', password = ?'
            params.append(hashed_password)
            app.logger.info(f'🔐 パスワードハッシュ生成成功')
        if current_user.employee_id:
            sql = f'UPDATE employees SET {base_sql} WHERE id = ? AND organization_id = ?'
            params.extend([current_user.employee_id, current_user.organization_id])
        else:
            sql = f'UPDATE employees SET {base_sql} WHERE email = ? AND organization_id = ?'
            params.extend([current_user.email, current_user.organization_id])
        cursor.execute(sql, params)
        app.logger.info(f'📝 SQL: {sql}, params: {params}')
        if hashed_password and current_user.employee_id:
            cursor.execute(
                'UPDATE users SET password = ? WHERE employee_id = ? AND organization_id = ?',
                (hashed_password, current_user.employee_id, current_user.organization_id)
            )
            app.logger.info('✅ usersテーブルのパスワードも更新しました')
        db.commit()
        app.logger.info('✅ プロフィール更新成功')
        return jsonify({'success': True})
    except Exception as e:
        db.rollback()
        app.logger.error(f'❌ プロフィール更新中にエラー: {e}')
        return jsonify({'error': 'プロフィール更新中にサーバーエラーが発生しました。'}), 500
    finally:
        db.close()

@app.route('/admin/employee/<int:employee_id>')
@login_required
@admin_required
@org_scoped_view
def admin_employee_view(employee_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            SELECT template_id FROM signature_assignments
            WHERE employee_id = ? AND organization_id = ?
            ORDER BY assigned_at DESC
            LIMIT 1
        ''', (employee_id, current_user.organization_id))
        row = cursor.fetchone()
        template_id = row['template_id'] if row else ''
        return render_template(
            'index.html',
            user_role='admin',
            initial_view='employee-portal',
            employee_id=employee_id,
            assigned_template_id=template_id
        )
    except sqlite3.Error as e:
        logging.error(f'❌ Error in admin_employee_view: {e}')
        return jsonify({'success': False, 'message': 'サーバーエラーが発生しました'}), 500
    finally:
        db.close()

@app.route('/admin/preview/<int:employee_id>')
@login_required
@admin_required
@org_scoped_view
def admin_preview(employee_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            SELECT template_id FROM signature_assignments
            WHERE employee_id = ? AND organization_id = ?
            ORDER BY assigned_at DESC LIMIT 1
        ''', (employee_id, current_user.organization_id))
        row = cursor.fetchone()
        template_id = row['template_id'] if row else ''
        return render_template(
            'index.html',
            user_role='admin',
            initial_view='employee-portal',
            preview_employee_id=employee_id,
            preview_template_id=template_id
        )
    except sqlite3.Error as e:
        logging.error(f'❌ Error in admin_preview: {e}')
        return jsonify({'success': False, 'message': 'サーバーエラーが発生しました'}), 500
    finally:
        db.close()

@app.route('/portal')
@login_required
@org_scoped_view
def portal_legacy():
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT id FROM employees WHERE email = ? AND organization_id = ?', 
                      (current_user.email, current_user.organization_id))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': '社員が見つかりません'}), 404
        employee_id = row['id']
        cursor.execute('''
            SELECT id FROM templates
            WHERE id IN (
                SELECT template_id FROM signature_assignments
                WHERE employee_id = ? AND organization_id = ?
                ORDER BY assigned_at DESC
                LIMIT 1
            )
        ''', (employee_id, current_user.organization_id))
        template_row = cursor.fetchone()
        template_id = template_row['id'] if template_row else ''
        return render_template(
            'index.html',
            user_role='employee',
            initial_view='employee-portal',
            employee_id=employee_id,
            assigned_template_id=template_id
        )
    except Exception as e:
        app.logger.exception('❌ エラー発生: /portal')
        return jsonify({'error': 'エラーが発生しました'}), 500
    finally:
        db.close()

@app.route('/api/employees', methods=['GET'])
@login_required
@org_scoped_view
def api_get_employees():
    try:
        page = int(request.args.get('page', 1))
        per_page = 15
        filter_name = request.args.get('filter_name')
        filter_email = request.args.get('filter_email')
        filter_department = request.args.get('filter_department')
        filter_role = request.args.get('filter_role')
        search = request.args.get('search')
        sort_by = request.args.get('sort_by')
        sort_order = request.args.get('sort_order', 'asc')
        result = get_employees(page, per_page, filter_name, filter_email, filter_department, filter_role, search, sort_by, sort_order)
        if result['success']:
            return jsonify(result)
        else:
            return jsonify({'success': False, 'message': result['message']}), 500
    except Exception as e:
        logging.error(f'❌ API get employees error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/employees/<int:id>', methods=['GET'])
@login_required
@org_scoped_view
def api_get_employee(id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM employees WHERE id = ? AND organization_id = ?', 
                      (id, current_user.organization_id))
        employee = cursor.fetchone()
        if employee:
            logging.info(f'✅ Employee retrieved: id={id}')
            return jsonify({'success': True, 'employee': dict(employee)})
        logging.warning(f'⚠️ Employee not found: id={id}')
        return jsonify({'success': False, 'message': '社員が見つかりません。'}), 404
    except sqlite3.Error as e:
        logging.error(f'❌ Get employee error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/employees/<int:id>', methods=['PUT'])
@login_required
@admin_required
@org_scoped_view
def api_update_employee(id):
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            UPDATE employees SET name = ?, email = ?, department = ?, role = ?
            WHERE id = ? AND organization_id = ?
        ''', (data['name'], data['email'], data['department'], data['role'], id, current_user.organization_id))
        if cursor.rowcount > 0:
            db.commit()
            logging.info(f'✅ Employee updated: id={id}')
            return jsonify({'success': True, 'message': '社員情報が更新されました。'})
        logging.warning(f'⚠️ Employee not found: id={id}')
        return jsonify({'success': False, 'message': '社員が見つかりません。'}), 404
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f'❌ Update employee error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/employees/<int:id>', methods=['DELETE'])
@login_required
@admin_required
@org_scoped_view
def api_delete_employee(id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('DELETE FROM employees WHERE id = ? AND organization_id = ?', 
                      (id, current_user.organization_id))
        if cursor.rowcount > 0:
            db.commit()
            logging.info(f'✅ Employee deleted: id={id}')
            return jsonify({'success': True, 'message': '社員が削除されました。'})
        logging.warning(f'⚠️ Employee not found: id={id}')
        return jsonify({'success': False, 'message': '社員が見つかりません。'}), 404
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f'❌ Delete employee error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/employees/import', methods=['POST'])
@login_required
@admin_required
@org_scoped_view
def api_import_employees():
    if 'file' not in request.files:
        return jsonify({'success': False, 'message': 'ファイルが選択されていません。'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'message': 'ファイルが選択されていません。'}), 400
    if file and file.filename.endswith('.csv'):
        db = get_db()
        try:
            cursor = db.cursor()
            stream = io.StringIO(file.stream.read().decode('UTF-8'), newline=None)
            csv_reader = csv.DictReader(stream)
            for row in csv_reader:
                name = row['name']
                email = row['email']
                department = row.get('department', '')
                role = row.get('role', 'employee')
                default_password = "password123"
                password_hash = generate_password_hash(default_password)
                cursor.execute('''
                    INSERT OR REPLACE INTO employees (name, email, department, role, organization_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (name, email, department, role, current_user.organization_id))
                cursor.execute('SELECT id FROM employees WHERE email = ? AND organization_id = ?', 
                              (email, current_user.organization_id))
                employee = cursor.fetchone()
                employee_id = employee['id'] if employee else None
                cursor.execute('''
                    INSERT OR REPLACE INTO users (email, role, password, employee_id, organization_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (email, role, password_hash, employee_id, current_user.organization_id))
            db.commit()
            return jsonify({'success': True, 'message': '社員が正常にインポートされました（初期PW: password123）'})
        except sqlite3.Error as e:
            db.rollback()
            return jsonify({'success': False, 'message': str(e)}), 500
        finally:
            db.close()
    return jsonify({'success': False, 'message': 'CSVファイルを選択してください。'}), 400

@app.route('/api/admin/assign-signatures', methods=['POST'])
@login_required
@admin_required
@org_scoped_view
def api_assign_signatures():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT id, department FROM campaigns WHERE organization_id = ?', 
                      (current_user.organization_id,))
        campaigns = cursor.fetchall()
        assigned_count = 0
        for campaign in campaigns:
            campaign_id = campaign['id']
            department = campaign['department']
            cursor.execute('SELECT id FROM templates WHERE campaign_id = ? AND organization_id = ?', 
                          (campaign_id, current_user.organization_id))
            template_rows = cursor.fetchall()
            template_ids = [row['id'] for row in template_rows]
            cursor.execute('SELECT id FROM employees WHERE department = ? AND organization_id = ?', 
                          (department, current_user.organization_id))
            employee_rows = cursor.fetchall()
            for employee in employee_rows:
                employee_id = employee['id']
                for template_id in template_ids:
                    cursor.execute('''
                        SELECT 1 FROM signature_assignments
                        WHERE employee_id = ? AND template_id = ? AND organization_id = ?
                    ''', (employee_id, template_id, current_user.organization_id))
                    exists = cursor.fetchone()
                    if not exists:
                        cursor.execute('''
                            INSERT INTO signature_assignments (employee_id, template_id, organization_id)
                            VALUES (?, ?, ?)
                        ''', (employee_id, template_id, current_user.organization_id))
                        assigned_count += 1
                        logging.info(f'✅ Assigned template_id={template_id} to employee_id={employee_id}')
        db.commit()
        return jsonify({
            'success': True,
            'message': f'部署に応じて署名テンプレートを自動割り当てしました（合計 {assigned_count} 件）'
        })
    except Exception as e:
        db.rollback()
        logging.error(f'❌ Error during auto signature assignment: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/templates', methods=['GET'])
@login_required
@org_scoped_view
def api_get_templates():
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM templates WHERE organization_id = ? ORDER BY created_at DESC', 
                      (current_user.organization_id,))
        templates = [dict(row) for row in cursor.fetchall()]
        logging.info(f'✅ Retrieved {len(templates)} templates')
        return jsonify(templates)
    except sqlite3.Error as e:
        logging.error(f'❌ Get templates error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/templates', methods=['POST'])
@login_required
@admin_required
@org_scoped_view
def api_create_template():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO templates (name, html_content, text_content, banner_url, organization_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (data['name'], data['html_content'], data['text_content'], data['banner_url'], current_user.organization_id))
        template_id = cursor.lastrowid
        html = data['html_content']
        def replace_tracking(match):
            link_text = match.group(1)
            track_id = shortuuid.uuid()
            track_url = url_for('api_track_click', track_id=track_id, _external=True)
            cursor.execute('''
                INSERT INTO tracking (track_id, url, template_id, employee_id, organization_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (track_id, link_text, template_id, current_user.employee_id, current_user.organization_id))
            return f'<a href="{track_url}" target="_blank">{link_text}</a>'
        pattern = r'<a href="\{\{tracking_link_temp_\d+\}\}" target="_blank">(.*?)<\/a>'
        updated_html = re.sub(pattern, replace_tracking, html)
        cursor.execute('UPDATE templates SET html_content = ? WHERE id = ?', (updated_html, template_id))
        db.commit()
        logging.info(f'✅ Template created and tracking URLs inserted: id={template_id}')
        return jsonify({'success': True, 'message': 'テンプレートが作成されました。', 'template_id': template_id})
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f'❌ Create template error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/templates/<int:id>', methods=['GET'])
@login_required
@org_scoped_view
def api_get_template(id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM templates WHERE id = ? AND organization_id = ?', 
                      (id, current_user.organization_id))
        template = cursor.fetchone()
        if template:
            logging.info(f'✅ Template retrieved: id={id}')
            return jsonify({'success': True, 'template': dict(template)})
        logging.warning(f'⚠️ Template not found: id={id}')
        return jsonify({'success': False, 'message': 'テンプレートが見つかりません。'}), 404
    except sqlite3.Error as e:
        logging.error(f'❌ Get template error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/templates/<int:id>', methods=['PUT'])
@login_required
@admin_required
@org_scoped_view
def api_update_template(id):
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            UPDATE templates SET name = ?, html_content = ?, text_content = ?, banner_url = ?
            WHERE id = ? AND organization_id = ?
        ''', (data['name'], data['html_content'], data['text_content'], data['banner_url'], id, current_user.organization_id))
        if cursor.rowcount > 0:
            db.commit()
            logging.info(f'✅ Template updated: id={id}')
            return jsonify({'success': True, 'message': 'テンプレートが更新されました。'})
        logging.warning(f'⚠️ Template not found: id={id}')
        return jsonify({'success': False, 'message': 'テンプレートが見つかりません。'}), 404
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f'❌ Update template error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/templates/<int:id>', methods=['DELETE'])
@login_required
@admin_required
@org_scoped_view
def api_delete_template(id):
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('DELETE FROM templates WHERE id = ? AND organization_id = ?', 
                      (id, current_user.organization_id))
        if cursor.rowcount == 0:
            logging.warning(f'⚠️ Template not found: id={id}')
            return jsonify({'success': False, 'message': 'テンプレートが見つかりません。'}), 404
        cursor.execute('SELECT id, template_ids FROM campaigns WHERE organization_id = ?', 
                      (current_user.organization_id,))
        for row in cursor.fetchall():
            cid = row['id']
            try:
                tids = json.loads(row['template_ids'] or "[]")
            except Exception:
                tids = []
            updated_tids = [tid for tid in tids if tid != id]
            if tids != updated_tids:
                cursor.execute(
                    'UPDATE campaigns SET template_ids = ? WHERE id = ? AND organization_id = ?',
                    (json.dumps(updated_tids), cid, current_user.organization_id)
                )
                logging.info(f'🔧 Campaign {cid} updated: removed template id {id}')
        db.commit()
        logging.info(f'✅ Template and references deleted: id={id}')
        return jsonify({'success': True, 'message': 'テンプレートが削除され、キャンペーンからも紐づきが除外されました。'})
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f'❌ Delete template error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/campaigns', methods=['GET'])
@login_required
@admin_required
@org_scoped_view
def api_get_campaigns():
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM campaigns WHERE organization_id = ?', (current_user.organization_id,))
        campaigns = cursor.fetchall()
        cursor.execute('SELECT id, name FROM templates WHERE organization_id = ?', (current_user.organization_id,))
        templates = {int(row['id']): row['name'] for row in cursor.fetchall()}
        result = []
        for c in campaigns:
            try:
                ids = json.loads(c['template_ids'] or '[]')
                ids = [int(tid) for tid in ids]
            except Exception:
                ids = []
            names = [templates[tid] for tid in ids if tid in templates]
            result.append({
                'id': c['id'],
                'department': c['department'],
                'template_ids': ids,
                'template_names': names,
                'start_date': c['start_date'],
                'end_date': c['end_date']
            })
        logging.info(f'✅ Retrieved {len(result)} campaigns')
        return jsonify(result)
    except Exception as e:
        logging.error(f'❌ Failed to load campaigns: {e}')
        return jsonify({'success': False, 'message': 'キャンペーン取得に失敗'}), 500
    finally:
        db.close()

@app.route('/api/campaigns', methods=['POST'])
@login_required
@admin_required
@org_scoped_view
def api_create_campaign():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    template_ids = data.get('template_ids', [])
    department = data.get('department')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    if not template_ids:
        return jsonify({'success': False, 'message': 'テンプレートが選択されていません。'}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO campaigns (template_ids, department, start_date, end_date, organization_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (json.dumps(template_ids), department, start_date, end_date, current_user.organization_id))
        campaign_id = cursor.lastrowid
        for tid in template_ids:
            cursor.execute('UPDATE templates SET campaign_id = ? WHERE id = ? AND organization_id = ?', 
                          (campaign_id, tid, current_user.organization_id))
        cursor.execute('SELECT id FROM employees WHERE department = ? AND organization_id = ?', 
                      (department, current_user.organization_id))
        employees = cursor.fetchall()
        for emp in employees:
            emp_id = emp['id']
            for tid in template_ids:
                cursor.execute('''
                    INSERT INTO signature_assignments (employee_id, template_id, applied_at, organization_id)
                    VALUES (?, ?, datetime('now'), ?)
                ''', (emp_id, tid, current_user.organization_id))
        db.commit()
        logging.info('✅ Campaign, templates, and assignments updated')
        return jsonify({'success': True, 'message': 'キャンペーンが作成され、署名が部署の従業員に割り当てられました。'})
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f'❌ Create campaign error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/campaigns/<int:id>', methods=['PUT'])
@login_required
@admin_required
@org_scoped_view
def update_campaign(id):
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    template_ids = data.get('template_ids', [])
    department = data.get('department')
    start_date = data.get('start_date')
    end_date = data.get('end_date')
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            UPDATE campaigns
            SET template_ids = ?, department = ?, start_date = ?, end_date = ?
            WHERE id = ? AND organization_id = ?
        ''', (json.dumps(template_ids), department, start_date, end_date, id, current_user.organization_id))
        if cursor.rowcount > 0:
            db.commit()
            return jsonify({'success': True, 'message': 'キャンペーンを更新しました'})
        return jsonify({'success': False, 'message': 'キャンペーンが見つかりません'}), 404
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/campaigns/<int:id>', methods=['DELETE'])
@login_required
@admin_required
@org_scoped_view
def delete_campaign(id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('DELETE FROM campaigns WHERE id = ? AND organization_id = ?', 
                      (id, current_user.organization_id))
        if cursor.rowcount > 0:
            db.commit()
            return jsonify({'success': True, 'message': 'キャンペーンを削除しました'})
        return jsonify({'success': False, 'message': 'キャンペーンが見つかりません'}), 404
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/departments', methods=['GET'])
@login_required
@org_scoped_view
def api_get_departments():
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT DISTINCT department FROM employees WHERE department IS NOT NULL AND organization_id = ?', 
                      (current_user.organization_id,))
        departments = [row['department'] for row in cursor.fetchall()]
        logging.info(f'✅ Retrieved {len(departments)} departments')
        return jsonify({'success': True, 'departments': departments})
    except sqlite3.Error as e:
        logging.error(f'❌ Get departments error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/signature_history', methods=['GET'])
@login_required
@org_scoped_view
def api_get_signature_history():
    db = get_db()
    try:
        cursor = db.cursor()
        query = '''
            SELECT sh.*, e.name as employee_name, t.name as template_name
            FROM signature_history sh
            JOIN employees e ON sh.employee_id = e.id
            JOIN templates t ON sh.template_id = t.id
            WHERE sh.organization_id = ? AND e.organization_id = ? AND t.organization_id = ?
        '''
        params = [current_user.organization_id, current_user.organization_id, current_user.organization_id]
        employee_id = request.args.get('employee_id')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        if employee_id:
            query += ' AND sh.employee_id = ?'
            params.append(employee_id)
        if start_date:
            query += ' AND sh.applied_at >= ?'
            params.append(start_date)
        if end_date:
            query += ' AND sh.applied_at <= ?'
            params.append(end_date)
        cursor.execute(query, params)
        history = [dict(row) for row in cursor.fetchall()]
        logging.info(f'✅ Retrieved {len(history)} signature history records')
        return jsonify(history)
    except sqlite3.Error as e:
        logging.error(f'❌ Get signature history error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/employee/signature', methods=['GET'])
@login_required
@org_scoped_view
def get_employee_signature():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        employee_id = current_user.employee_id or current_user.id
        cursor.execute('''
            SELECT t.id AS template_id, t.html_content, t.text_content, t.banner_url
            FROM templates t
            JOIN signature_assignments sa ON t.id = sa.template_id
            WHERE sa.employee_id = ? AND t.organization_id = ? AND sa.organization_id = ?
            ORDER BY COALESCE(sa.applied_at, sa.assigned_at) DESC
            LIMIT 1
        ''', (employee_id, current_user.organization_id, current_user.organization_id))
        signature = cursor.fetchone()
        if not signature:
            app.logger.warning(f'⚠️ No signature found for employee_id: {employee_id}')
            return jsonify({'success': False, 'message': '署名が見つかりませんでした'}), 404
        cursor.execute('SELECT * FROM employees WHERE id = ? AND organization_id = ?', 
                      (employee_id, current_user.organization_id))
        employee = cursor.fetchone()
        if not employee:
            app.logger.warning(f'❌ No employee record found for ID: {employee_id}')
            return jsonify({'success': False, 'message': '社員情報が見つかりませんでした'}), 404
        cursor.execute('SELECT name FROM organizations WHERE id = ?', (employee['organization_id'],))
        org = cursor.fetchone()
        company_name = org['name'] if org else '未登録'
        variables = {
            'name': employee['name'],
            'email': employee['email'],
            'role': employee['role'],
            'department': employee['department'],
            'company': company_name,
            'phone': employee['phone'] if employee['phone'] else '未登録',
            'address': employee['address'] if employee['address'] else '未登録',
            'website': employee['website'] if employee['website'] else '未登録',
            'linkedin': employee['linkedin'] if employee['linkedin'] else '未登録',
            'banner_url': signature['banner_url'] if signature['banner_url'] else '未登録'
        }
        rendered_html = render_signature_template(signature['html_content'], variables)
        final_html = replace_links_with_tracking(rendered_html, employee['id'], signature['template_id'])
        return jsonify({
            'success': True,
            'signature': {
                'html_content': final_html,
                'text_content': signature['text_content']
            }
        })
    except Exception as e:
        app.logger.error(f'❌ Error in /api/employee/signature: {str(e)}')
        return jsonify({'success': False, 'message': f'サーバーエラー: {str(e)}'}), 500
    finally:
        conn.close()

@app.route('/api/employee/signature', methods=['POST'])
@login_required
@org_scoped_view
def apply_signature():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    template_id = data.get('template_id')
    if not template_id:
        return jsonify({'success': False, 'message': 'テンプレートIDが必要です'}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM templates WHERE id = ? AND organization_id = ?', 
                      (template_id, current_user.organization_id))
        template = cursor.fetchone()
        if not template:
            return jsonify({'success': False, 'message': 'テンプレートが存在しません'}), 404
        cursor.execute('SELECT * FROM employees WHERE id = ? AND organization_id = ?', 
                      (current_user.employee_id, current_user.organization_id))
        employee = cursor.fetchone()
        if not employee:
            return jsonify({'success': False, 'message': '社員情報が見つかりません'}), 404
        cursor.execute('SELECT name FROM organizations WHERE id = ?', (employee['organization_id'],))
        org = cursor.fetchone()
        company_name = org['name'] if org else '未登録'
        variables = {
            'name': employee['name'],
            'email': employee['email'],
            'role': employee['role'],
            'department': employee['department'],
            'company': company_name,
            'phone': employee['phone'] or '未登録',
            'address': employee['address'] or '未登録',
            'website': employee['website'] or '未登録',
            'linkedin': employee['linkedin'] or '未登録',
            'banner_url': template['banner_url'] or ''
        }
        html_filled = render_signature_template(template['html_content'], variables)
        html_final = replace_links_with_tracking(html_filled, employee['id'], template_id)
        cursor.execute('''
            INSERT INTO signature_history (employee_id, template_id, organization_id) 
            VALUES (?, ?, ?)
        ''', (employee['id'], template_id, current_user.organization_id))
        db.commit()
        return jsonify({'success': True, 'signature_html': html_final})
    except Exception as e:
        db.rollback()
        logging.error(f'❌ Signature apply error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/render_signature', methods=['POST'])
@login_required
@employee_required
@org_scoped_view
def render_signature_api():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    template_id = data.get('template_id')
    if not template_id:
        return jsonify({'success': False, 'message': 'テンプレートIDが必要です'}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT html_content FROM templates WHERE id = ? AND organization_id = ?', 
                      (template_id, current_user.organization_id))
        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'テンプレートが見つかりません'}), 404
        template_html = row['html_content']
        cursor.execute('SELECT * FROM employees WHERE id = ? AND organization_id = ?', 
                      (current_user.employee_id, current_user.organization_id))
        employee = cursor.fetchone()
        if not employee:
            return jsonify({'success': False, 'message': '社員情報が見つかりません'}), 404
        cursor.execute('SELECT name FROM organizations WHERE id = ?', (employee['organization_id'],))
        org = cursor.fetchone()
        company_name = org['name'] if org else '未登録'
        rendered_html = render_signature_template(template_html, {
            'name': employee.get('name', ''),
            'email': employee.get('email', ''),
            'department': employee.get('department', ''),
            'role': employee.get('role', ''),
            'company': company_name,
            'phone': employee.get('phone', ''),
            'address': employee.get('address', ''),
            'website': employee.get('website', ''),
            'linkedin': employee.get('linkedin', ''),
            'banner_url': employee.get('banner_url', '')
        })
        final_html = replace_links_with_tracking(rendered_html, current_user.employee_id, template_id)
        return jsonify({'success': True, 'signature_html': final_html})
    except Exception as e:
        logging.exception('❌ 署名生成エラー')
        return jsonify({'success': False, 'message': 'エラーが発生しました'}), 500
    finally:
        db.close()

@app.route('/api/generate_track', methods=['POST'])
@login_required
@org_scoped_view
def generate_track():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    url = data.get('url')
    template_id = data.get('templateId') or data.get('template_id')
    employee_id = data.get('employeeId') or data.get('employee_id')
    logging.info(f'📥 tracking生成リクエスト受信: url={url}, template_id={template_id}, employee_id={employee_id}')
    if not url or not employee_id:
        return jsonify({'success': False, 'message': 'URLとemployee_idは必須です'}), 400
    track_id = shortuuid.uuid()
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO tracking (track_id, url, template_id, employee_id, clicks, created_at, organization_id)
            VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP, ?)
        ''', (track_id, url, template_id, employee_id, current_user.organization_id))
        db.commit()
        track_url = url_for('api_track_click', track_id=track_id, _external=True)
        logging.info(f'✅ tracking生成成功: track_id={track_id}, url={url}, track_url={track_url}')
        return jsonify({'success': True, 'track_url': track_url})
    except Exception as e:
        db.rollback()
        logging.exception('❌ tracking生成中にエラー発生')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/click/<track_id>', methods=['GET'])
@login_required
@org_scoped_view
def api_track_click(track_id):
    db = get_db()
    db.row_factory = sqlite3.Row
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM tracking WHERE track_id = ? AND organization_id = ?', 
                      (track_id, current_user.organization_id))
        track = cursor.fetchone()
        if not track:
            logging.warning(f'⚠️ トラッキングIDが見つかりません: {track_id}')
            return jsonify({'success': False, 'message': 'トラッキングが見つかりません'}), 404
        ip = request.remote_addr
        ua = request.headers.get('User-Agent', 'unknown')
        now = datetime.utcnow()
        now_str = now.isoformat()
        cookie_key = f'track_{track_id}'
        clicked_cookie = request.cookies.get(cookie_key)
        logging.info(f'🧪 Click attempt: track_id={track_id}, ip={ip}, ua={ua}, cookie={clicked_cookie}')
        if clicked_cookie:
            logging.info(f'🍪 Cookie blocked: {track_id}')
            return redirect(track['url'])
        cursor.execute('''
            SELECT created_at FROM analytics
            WHERE track_id = ? AND ip = ? AND organization_id = ?
            ORDER BY created_at DESC LIMIT 1
        ''', (track_id, ip, current_user.organization_id))
        row = cursor.fetchone()
        if row and row['created_at']:
            last_click = datetime.fromisoformat(row['created_at']) if isinstance(row['created_at'], str) else row['created_at']
            if (now - last_click).total_seconds() < 10:
                logging.info(f'🛑 IP timing blocked (10秒以内): {track_id}')
                return redirect(track['url'])
        resp = make_response(redirect(track['url']))
        resp.set_cookie(cookie_key, 'clicked', max_age=60, httponly=True)
        cursor.execute('UPDATE tracking SET clicks = clicks + 1 WHERE track_id = ? AND organization_id = ?', 
                      (track_id, current_user.organization_id))
        cursor.execute('''
            INSERT INTO analytics (track_id, template_id, employee_id, ip, user_agent, created_at, organization_id)
            SELECT track_id, template_id, employee_id, ?, ?, ?, ?
            FROM tracking
            WHERE track_id = ? AND organization_id = ?
        ''', (ip, ua, now_str, current_user.organization_id, track_id, current_user.organization_id))
        db.commit()
        logging.info(f'✅ Click tracked: {track_id} (cookie + ip checked)')
        return resp
    except Exception as e:
        logging.error(f'❌ Error tracking click: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/check_track_exists/<track_id>')
@login_required
@org_scoped_view
def check_track_exists(track_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT url FROM tracking WHERE track_id = ? AND organization_id = ?', 
                      (track_id, current_user.organization_id))
        row = cursor.fetchone()
        exists = row is not None and bool(row['url'])
        return jsonify({'exists': exists}), 200
    except Exception as e:
        logging.error(f'❌ DBエラー: {e}')
        return jsonify({'exists': False, 'error': 'DBエラー'}), 500
    finally:
        db.close()

@app.route('/api/save_template', methods=['POST'])
@login_required
@org_scoped_view
def save_template():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    html = data.get('html', '')
    if '{{tracking_link_temp_' in html:
        return jsonify({'success': False, 'message': '一時リンクが残っています。コピー前に必ず置換してください。'}), 400
    return jsonify({'success': True, 'message': 'テンプレートを保存しました'})

@app.route('/debug/employee-clicks')
@login_required
@org_scoped_view
def debug_employee_clicks():
    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute('''
            SELECT e.id AS employee_id,
                   e.name AS employee_name,
                   COUNT(a.id) AS clicks
            FROM analytics a
            LEFT JOIN employees e ON a.employee_id = e.id
            WHERE DATE(a.clicked_at) BETWEEN '2025-06-11' AND '2025-06-19'
            AND a.organization_id = ? AND e.organization_id = ?
            GROUP BY e.id
        ''', (current_user.organization_id, current_user.organization_id))
        rows = cursor.fetchall()
        output = '<h2>社員ごとのクリック数</h2><table border="1"><tr><th>ID</th><th>名前</th><th>クリック数</th></tr>'
        for row in rows:
            output += f'<tr><td>{row["employee_id"]}</td><td>{row["employee_name"]}</td><td>{row["clicks"]}</td></tr>'
        output += '</table>'
        return output
    except Exception as e:
        return f'<p>エラー: {e}</p>'
    finally:
        db.close()

@app.route('/api/analytics', methods=['GET'])
@login_required
@org_scoped_view
def api_get_analytics():
    db = get_db()
    try:
        cursor = db.cursor()
        query = '''
            SELECT a.id,
                   a.track_id,
                   a.template_id,
                   a.employee_id,
                   a.clicked_at,
                   COALESCE(t.name, '不明') AS template_name,
                   COALESCE(e.name, '不明') AS employee_name,
                   COALESCE(e.department, '不明') AS department
            FROM analytics a
            JOIN tracking tr ON a.track_id = tr.track_id
            LEFT JOIN templates t ON a.template_id = t.id
            LEFT JOIN employees e ON a.employee_id = e.id
            WHERE e.organization_id = ?
        '''
        params = [current_user.organization_id]
        if request.args.get('start_date'):
            query += ' AND date(a.clicked_at) >= date(?)'
            params.append(request.args.get('start_date'))
        if request.args.get('end_date'):
            query += ' AND date(a.clicked_at) <= date(?)'
            params.append(request.args.get('end_date'))
        if request.args.get('track_id'):
            query += ' AND a.track_id = ?'
            params.append(request.args.get('track_id'))
        cursor.execute(query, params)
        analytics = [dict(row) for row in cursor.fetchall()]
        logging.info(f'✅ Retrieved {len(analytics)} analytics records')
        return jsonify(analytics)
    except sqlite3.Error as e:
        logging.error(f'❌ Get analytics error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/employee-analytics')
@login_required
@org_scoped_view
def employee_analytics():
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        logger.info('🧠 /api/employee-analytics start=%s end=%s', start_date, end_date)
        if not start_date or not end_date:
            return jsonify([])
        db = get_db()
        cursor = db.cursor()
        query = '''
            SELECT e.id AS employee_id,
                   e.name AS employee_name,
                   e.department AS department,
                   COUNT(*) AS clicks
            FROM analytics a
            JOIN employees e ON a.employee_id = e.id
            WHERE DATE(datetime(a.clicked_at, '+9 hours')) BETWEEN DATE(?) AND DATE(?)
            AND a.organization_id = ? AND e.organization_id = ?
            GROUP BY e.id
        '''
        cursor.execute(query, (start_date, end_date, current_user.organization_id, current_user.organization_id))
        rows = cursor.fetchall()
        result = [{
            'employee_id': row['employee_id'],
            'employee_name': row['employee_name'],
            'department': row['department'],
            'clicks': row['clicks']
        } for row in rows]
        logger.info('✅ /api/employee-analytics returned %d rows', len(result))
        return jsonify(result)
    except Exception as e:
        logger.exception('❌ /api/employee-analytics failed:')
        return jsonify({'error': 'Internal server error'}), 500
    finally:
        db.close()

@app.route('/api/analytics/department', methods=['GET'])
@login_required
@org_scoped_view
def api_get_department_analytics():
    try:
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        logger.info('🧠 /api/analytics/department start=%s end=%s', start_date, end_date)
        if not start_date or not end_date:
            return jsonify({'success': False, 'message': '開始日と終了日を指定してください'}), 400
        db = get_db()
        cursor = db.cursor()
        query = '''
            SELECT e.department, COUNT(a.id) as clicks
            FROM analytics a
            JOIN employees e ON a.employee_id = e.id
            WHERE DATE(datetime(a.clicked_at, '+9 hours')) BETWEEN DATE(?) AND DATE(?)
            AND a.organization_id = ? AND e.organization_id = ?
            GROUP BY e.department
        '''
        cursor.execute(query, (start_date, end_date, current_user.organization_id, current_user.organization_id))
        rows = cursor.fetchall()
        result = [{
            'department': row['department'],
            'clicks': row['clicks']
        } for row in rows]
        logger.info('✅ /api/analytics/department returned %d rows', len(result))
        return jsonify({'success': True, 'data': result})
    except sqlite3.Error as e:
        logger.error(f'❌ Get department analytics error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/signature_template', methods=['POST'])
@login_required
@org_scoped_view
def save_signature_template():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    html = data.get('html')
    employee_id = data.get('employee_id', current_user.employee_id)
    if not html or not employee_id:
        return jsonify({'success': False, 'message': 'HTMLと社員IDが必要です'}), 400
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO signature_templates (employee_id, html, organization_id)
            VALUES (?, ?, ?)
        ''', (employee_id, html, current_user.organization_id))
        db.commit()
        logger.info(f'✅ Signature template saved for employee_id={employee_id}')
        return jsonify({'success': True, 'message': '署名テンプレートが保存されました'})
    except sqlite3.Error as e:
        db.rollback()
        logger.error(f'❌ Save signature template error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/signature_template/<int:employee_id>', methods=['GET'])
@login_required
@org_scoped_view
def get_signature_template(employee_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            SELECT * FROM signature_templates
            WHERE employee_id = ? AND organization_id = ?
            ORDER BY created_at DESC LIMIT 1
        ''', (employee_id, current_user.organization_id))
        template = cursor.fetchone()
        if template:
            logger.info(f'✅ Signature template retrieved for employee_id={employee_id}')
            return jsonify({'success': True, 'template': dict(template)})
        logger.warning(f'⚠️ No signature template found for employee_id={employee_id}')
        return jsonify({'success': False, 'message': '署名テンプレートが見つかりません'}), 404
    except sqlite3.Error as e:
        logger.error(f'❌ Get signature template error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/tracking_links', methods=['POST'])
@login_required
@admin_required
@org_scoped_view
def create_tracking_link():
    try:
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError:
        return jsonify({'success': False, 'message': 'CSRFトークンが無効です'}), 400
    data = request.get_json()
    template_id = data.get('template_id')
    placeholder = data.get('placeholder')
    label = data.get('label')
    original_url = data.get('original_url')
    if not all([template_id, placeholder, original_url]):
        return jsonify({'success': False, 'message': 'テンプレートID、プレースホルダー、URLが必要です'}), 400
    track_id = shortuuid.uuid()
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            INSERT INTO tracking_links (template_id, placeholder, label, original_url, track_id, organization_id)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (template_id, placeholder, label, original_url, track_id, current_user.organization_id))
        db.commit()
        track_url = url_for('api_track_click', track_id=track_id, _external=True)
        logger.info(f'✅ Tracking link created: track_id={track_id}, url={original_url}')
        return jsonify({'success': True, 'track_url': track_url, 'track_id': track_id})
    except sqlite3.Error as e:
        db.rollback()
        logger.error(f'❌ Create tracking link error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/tracking_links/<int:template_id>', methods=['GET'])
@login_required
@org_scoped_view
def get_tracking_links(template_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            SELECT * FROM tracking_links
            WHERE template_id = ? AND organization_id = ?
        ''', (template_id, current_user.organization_id))
        links = [dict(row) for row in cursor.fetchall()]
        logger.info(f'✅ Retrieved {len(links)} tracking links for template_id={template_id}')
        return jsonify({'success': True, 'links': links})
    except sqlite3.Error as e:
        logger.error(f'❌ Get tracking links error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/statistics', methods=['GET'])
@login_required

def api_get_statistics():
    """統計データを取得（企業ごとに制限）"""
    db = get_db()
    try:
        cursor = db.cursor()
        org_id = current_user.organization_id  # ← 🔒 ここ重要

        cursor.execute('''
            SELECT t.id as tid, 
                   (SELECT COUNT(*) FROM analytics a2 WHERE a2.track_id = t.track_id) as clicks,
                   e.name as employee_name
            FROM tracking t
            LEFT JOIN employees e ON t.employee_id = e.id
            WHERE e.organization_id = ?
        ''', (org_id,))
        
        data = [dict(row) for row in cursor.fetchall()]
        logging.info(f'✅ Retrieved statistics: {len(data)} records (org_id={org_id})')
        return jsonify(data)

    except sqlite3.Error as e:
        logging.error(f'❌ Get statistics error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        db.close()

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory(app.static_folder, filename)

# アプリケーションの開始
if __name__ == '__main__':
    init_db()
    app.run(debug=True, host='0.0.0.0', port=10000)