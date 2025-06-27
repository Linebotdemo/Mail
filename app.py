import os
import csv
import io
import json
from datetime import date
from flask_wtf import CSRFProtect  # ✅ これだけでOK
from flask import Flask, jsonify, session
from flask_login import LoginManager, logout_user, login_required, current_user
import sqlite3
import logging
import shortuuid
from flask_login import current_user
from datetime import datetime
from fastapi import Request
import traceback
from flask import jsonify, redirect, url_for
from werkzeug.exceptions import InternalServerError
from flask import jsonify, request
from flask import redirect, url_for, jsonify
from functools import wraps
from urllib.parse import urlparse, parse_qs
import secrets
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, abort, flash, send_from_directory, current_app
from flask_login import LoginManager, UserMixin, login_user, logout_user, current_user, login_required
from flask_wtf import FlaskForm
from flask import request, jsonify, abort
from flask_wtf.csrf import CSRFProtect
from jinja2 import Template
from flask_wtf.csrf import validate_csrf, CSRFError
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import request, render_template, redirect

# Flask アプリケーションの初期化
app = Flask(__name__, static_folder='static')
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(16))
app = Flask(__name__)
app.secret_key = 'your-secret-key'
csrf = CSRFProtect(app)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "dev-secret")
# ログ設定
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] (%(pathname)s:%(lineno)d) %(message)s'
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

app.config['WTF_CSRF_ENABLED'] = False

csrf = CSRFProtect()
csrf.init_app(app)

# データベース設定
DATABASE = 'database.db'

def employee_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if current_user.role != 'employee':
            return jsonify({'success': False, 'message': '社員権限が必要です。'}), 403
        return f(*args, **kwargs)
    return decorated_function

from bs4 import BeautifulSoup




def get_db():
    try:
        db = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
        logging.info(f'✅ Database connection established: {DATABASE}')
        return db
    except sqlite3.Error as e:
        logging.error(f'❌ Database connection failed: {e}')
        raise

# ✅ トラッキングURL変換（オプション）
def store_click_tracking(track_id, employee_id, template_id, url):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO tracking (track_id, url, employee_id, template_id, clicks)
        VALUES (?, ?, ?, ?, 0)
    ''', (track_id, url, employee_id, template_id))
    db.commit()
    db.close()


def init_db():
    with app.app_context():
        db = get_db()
        cursor = db.cursor()
        try:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'employee',
                    employee_id INTEGER
                )
            ''')
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
                    linkedin TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    html_content TEXT,
                    text_content TEXT,
                    banner_url TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    campaign_id INTEGER
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    template_ids TEXT NOT NULL,
                    department TEXT,
                    start_date TIMESTAMP NOT NULL,
                    end_date TIMESTAMP NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signature_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER,
                    template_id INTEGER,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    track_id TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    template_id INTEGER,
                    employee_id INTEGER,
                    clicks INTEGER DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signature_assignments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER NOT NULL,
                    template_id INTEGER NOT NULL,
                    assigned_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    applied_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
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
                    created_at TEXT
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signature_templates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    employee_id INTEGER NOT NULL,
                    html TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS organizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL
                )
            ''')
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS tracking_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    template_id INTEGER NOT NULL,
                    placeholder TEXT NOT NULL,
                    label TEXT,
                    original_url TEXT NOT NULL,
                    track_id TEXT UNIQUE NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            # ✅ カラム追加チェック（存在しない場合のみ追加）
            cursor.execute("PRAGMA table_info(users)")
            user_columns = [col[1] for col in cursor.fetchall()]
            if 'organization_id' not in user_columns:
                cursor.execute("ALTER TABLE users ADD COLUMN organization_id INTEGER")

            cursor.execute("PRAGMA table_info(employees)")
            emp_columns = [col[1] for col in cursor.fetchall()]
            if 'organization_id' not in emp_columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN organization_id INTEGER")
            if 'password' not in emp_columns:
                cursor.execute("ALTER TABLE employees ADD COLUMN password TEXT")

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
    def __init__(self, id, email, role, employee_id=None, department=None):
        self.id = id
        self.email = email
        self.role = role
        self.employee_id = employee_id
        self.department = department

    def get_id(self):
        return str(self.id)




# Flask-Login 設定
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'auth'

@login_manager.user_loader
def load_user(user_id):
    """ユーザーIDからユーザーをロードする（employee_id付き）"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = cursor.fetchone()
        if user:
            logging.info(f'✅ User loaded: {user["email"]}')
            employee_id = user['employee_id'] if 'employee_id' in user.keys() else None
            return User(user['id'], user['email'], user['role'], employee_id)
        logging.warning(f'⚠️ User not found: id={user_id}')
        return None
    except sqlite3.Error as e:
        logging.error(f'❌ User load failed: {e}')
        return None
    finally:
        db.close()

def render_signature_template(template_html, variables):
    template = Template(template_html)
    return template.render(**variables)



def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    app.logger.info('✅ Database connection established: database.db')
    return conn

# カスタムフィルタ: strftime
def format_datetime(value, format='%Y-%m-%d %H:%M:%S'):
    """Jinja2 テンプレート用の strftime フィルタ"""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace('Z', '+00:00'))
        except ValueError:
            return value
    return value.strftime(format)

# カスタムフィルタ: from_json
def from_json(value):
    """Jinja2 テンプレート用の from_json フィルタ"""
    if value is None:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError as e:
        logging.error(f'❌ JSON decode error in from_json filter: {e}')
        return value

def replace_links_with_tracking(html, employee_id, template_id):
    from bs4 import BeautifulSoup
    import shortuuid
    from flask import url_for

    db = get_db()
    cursor = db.cursor()
    soup = BeautifulSoup(html, "html.parser")

    for a in soup.find_all("a", href=True):
        original_url = a["href"]

        # 元URLに戻す処理（もし /click/ を含んでたら）
        if '/click/' in original_url:
            track_id = original_url.split('/click/')[-1]
            cursor.execute('SELECT url FROM tracking WHERE track_id = ?', (track_id,))
            row = cursor.fetchone()
            if row:
                original_url = row['url']

        # 🔒 社員ごとに個別トラッキングIDを作成・再利用
        cursor.execute('''
            SELECT * FROM tracking WHERE url = ? AND employee_id = ? AND template_id = ?
        ''', (original_url, employee_id, template_id))
        existing = cursor.fetchone()

        if existing:
            track_id = existing['track_id']
        else:
            track_id = shortuuid.uuid()
            cursor.execute('''
                INSERT INTO tracking (track_id, url, employee_id, template_id, clicks)
                VALUES (?, ?, ?, ?, 0)
            ''', (track_id, original_url, employee_id, template_id))
            db.commit()

        # 常に自分のトラッキングURLに変換
        a['href'] = url_for('api_track_click', track_id=track_id, _external=True)

    return str(soup)




app.jinja_env.filters['strftime'] = format_datetime
app.jinja_env.filters['from_json'] = from_json

@app.route('/api/me', methods=['GET', 'POST'])
@login_required
def me():
    if request.method == 'GET':
        return jsonify(success=True, user={
            'id': current_user.id,
            'name': current_user.name,
            'email': current_user.email,
            'department': current_user.department,
        })
    else:
        data = request.form
        current_user.name = data.get('name')
        current_user.email = data.get('email')
        current_user.department = data.get('department')
        db.session.commit()
        return jsonify(success=True, message="プロフィールを更新しました")

@app.route('/api/profile', methods=['POST'])
@login_required
def update_profile():
    data = request.get_json()
    app.logger.info(f'🟡 受信データ: {data}')
    db = get_db()
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
        sql = f'UPDATE employees SET {base_sql} WHERE id = ?'
        params.append(current_user.employee_id)
    else:
        sql = f'UPDATE employees SET {base_sql} WHERE email = ?'
        params.append(current_user.email)

    try:
        cursor.execute(sql, params)
        app.logger.info(f'📝 SQL: {sql}, params: {params}')

        # 🔁 usersテーブルのパスワードも更新（必要な場合のみ）
        if hashed_password and current_user.employee_id:
            cursor.execute(
                'UPDATE users SET password = ? WHERE employee_id = ?',
                (hashed_password, current_user.employee_id)
            )
            app.logger.info('✅ usersテーブルのパスワードも更新しました')

        db.commit()
        app.logger.info('✅ プロフィール更新成功')
        return jsonify(success=True)
    except Exception as e:
        db.rollback()
        app.logger.error(f'❌ プロフィール更新中にエラー: {e}')
        return jsonify({'error': 'プロフィール更新中にサーバーエラーが発生しました。'}), 500
    finally:
        db.close()






@app.route('/api/profile', methods=['GET'])
@login_required
def get_profile():
    try:
        app.logger.info('✅ /api/profile route loaded')
        db = get_db()
        cursor = db.cursor()

        if current_user.employee_id:
            cursor.execute('SELECT * FROM employees WHERE id = ?', (current_user.employee_id,))
            row = cursor.fetchone()
            if row:
                profile = dict(zip([column[0] for column in cursor.description], row))
                app.logger.info(f'✅ Profile retrieved for employee_id: {current_user.employee_id}')
                return jsonify(profile)
            else:
                app.logger.warning(f'⚠️ No employee found for employee_id: {current_user.employee_id}')
                return jsonify({'error': '社員情報が見つかりませんでした。管理者にお問い合わせください。'}), 404
        else:
            app.logger.warning(f'⚠️ No employee_id set for user: {current_user.email}, trying email lookup')
            cursor.execute('SELECT * FROM employees WHERE email = ?', (current_user.email,))
            row = cursor.fetchone()
            if row:
                profile = dict(zip([column[0] for column in cursor.description], row))  # ← 修正済み
                app.logger.info(f'✅ Profile retrieved for email: {current_user.email}')
                return jsonify(profile)
            else:
                app.logger.warning(f'⚠️ No employee found for email: {current_user.email}')
                return jsonify({'error': 'プロフィール情報が見つかりませんでした。管理者による設定が必要です。'}), 404
    except Exception as e:
        app.logger.error(f'❌ Error in /api/profile: {str(e)}')
        return jsonify({'error': 'サーバーエラーが発生しました。後でもう一度お試しください。'}), 500
    finally:
        if 'db' in locals():
            db.close()


# エラーハンドリング
@app.errorhandler(404)
def page_not_found(e):
    """404 エラーハンドラ"""
    logging.warning(f'❌ 404 error: path={request.path}')
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_server_error(e):
    """500 エラーハンドラ"""
    logging.error(f'❌ 500 error: {str(e)}')
    return jsonify({'error': 'Internal server error'}), 500

# 認証チェックデコレータ
def admin_required(f):
    """管理者権限を要求するデコレータ"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            logging.warning(f'⚠️ Unauthorized access attempt: {request.path}')
            flash('管理者権限が必要です。', 'danger')
            return redirect(url_for('auth'))
        return f(*args, **kwargs)
    return decorated_function




from flask import url_for, request

def generate_track_url(track_id):
    return url_for('api_track_click', track_id=track_id, _external=True)  # ← https://yourdomain.com/click/xxx


def get_campaigns():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM campaigns")
    rows = cursor.fetchall()
    db.close()
    return rows

def get_templates():
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM templates")
    rows = cursor.fetchall()
    db.close()
    return rows


# ルート
@app.route("/")
@login_required
def index():
    user = current_user
    employee_id = ""
    template_id = ""

    logger.debug("✅ ログインユーザー: %s (%s)", user.email, user.role)

    if user.role == "社員":
        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT id FROM employees WHERE email = ?", (user.email,))
        row = cursor.fetchone()
        logger.debug("📌 employees row: %s", row)

        if row:
            employee_id = row["id"]
            logger.debug("📌 employee_id: %s", employee_id)

            cursor.execute("""
                SELECT template_id FROM signature_assignments
                WHERE employee_id = ?
                ORDER BY assigned_at DESC
                LIMIT 1
            """, (employee_id,))
            assigned = cursor.fetchone()
            logger.debug("📌 assigned row: %s", assigned)

            template_id = assigned["template_id"] if assigned else ""
            logger.debug("📌 template_id: %s", template_id)

        db.close()

    return render_template(
        "index.html",
        user_role=user.role,
        employee_id=employee_id,
        assigned_template_id=template_id,
        initial_view="employee-portal" if user.role == "社員" else "admin-dashboard",
        campaigns=get_campaigns(),
        templates=get_templates()
    )


@app.route('/admin/preview/<int:employee_id>')
@login_required
def admin_preview(employee_id):
    db = get_db()
    cursor = db.cursor()

    cursor.execute("""
        SELECT template_id FROM signature_assignments
        WHERE employee_id = ?
        ORDER BY assigned_at DESC LIMIT 1
    """, (employee_id,))
    row = cursor.fetchone()
    template_id = row["template_id"] if row else ''

    return render_template(
        "index.html",
        user_role="admin",
        initial_view="employee-portal",
        preview_employee_id=employee_id,
        preview_template_id=template_id
    )

@app.route("/admin/employee/<int:employee_id>")
@login_required
def admin_employee_view(employee_id):
    if current_user.role != "admin":
        return redirect("/portal")

    db = get_db()
    cursor = db.cursor()

    # テンプレートIDの取得
    cursor.execute("""
        SELECT template_id FROM signature_assignments
        WHERE employee_id = ?
        ORDER BY assigned_at DESC
        LIMIT 1
    """, (employee_id,))
    row = cursor.fetchone()
    template_id = row["template_id"] if row else ""

    return render_template(
        "index.html",
        user_role="admin",
        initial_view="employee-portal",
        employee_id=employee_id,
        assigned_template_id=template_id
    )




@app.route('/portal')
@login_required
def portal_legacy():
    try:
        db = get_db()
        cursor = db.cursor()

        cursor.execute("SELECT id FROM employees WHERE email = ?", (current_user.email,))
        row = cursor.fetchone()
        if not row:
            return "社員が見つかりません", 404

        employee_id = row["id"]

        cursor.execute("""
            SELECT id FROM templates
            WHERE id IN (
                SELECT template_id FROM signature_assignments
                WHERE employee_id = ?
                ORDER BY assigned_at DESC
                LIMIT 1
            )
        """, (employee_id,))
        template_row = cursor.fetchone()
        template_id = template_row["id"] if template_row else ''

        return render_template(
            "index.html",
            user_role="employee",  # 🔽 追加
            initial_view="employee-portal",  # 🔽 追加
            employee_id=employee_id,
            assigned_template_id=template_id
        )

    except Exception as e:
        app.logger.exception("❌ エラー発生: /portal")
        return "エラーが発生しました", 500
    finally:
        db.close()






@app.route('/auth', methods=['GET', 'POST'])
def auth():
    """認証ページを処理"""
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
                    user_obj = User(user['id'], user['email'], user['role'], user['employee_id'])
                    login_user(user_obj)
                    session['user_id'] = user['id']
                    logging.info(f'✅ Login successful: {email}')
                    next_page = request.args.get('next', url_for('index'))
                    return redirect(next_page)
                else:
                    logging.warning(f'⚠️ Login failed: {email}')
                    flash('無効なメールアドレスまたはパスワードです。', 'danger')
            except sqlite3.Error as e:
                logging.error(f'❌ Login error: {e}')
                flash('サーバーエラーが発生しました。', 'danger')
            finally:
                db.close()

    logging.info('🔵 Rendering auth page')
    return render_template('auth.html', form=form)


@app.route('/api/login', methods=['POST'])
@csrf.exempt  # テスト用に CSRF を無効化（本番では script.js でトークンを送信）
def login():
    """API 経由でログインを処理"""
    try:
        data = request.get_json(force=True)
        email = data.get('email')
        password = data.get('password')
        if not email or not password:
            logging.warning(f'⚠️ Missing email or password: {email}')
            return jsonify({'success': False, 'message': 'メールとパスワードを入力してください'}), 400
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        if user and check_password_hash(user['password'], password):
            user_obj = User(user['id'], user['email'], user['role'], user['employee_id'])
            login_user(user_obj)
            logging.info(f'✅ Login successful: {email}')
            return jsonify({'success': True, 'redirect': '/'})
        logging.warning(f'⚠️ Login failed: {email}')
        return jsonify({'success': False, 'message': '無効な認証情報です。'}), 401
    except Exception as e:
        logging.exception(f'❌ Login error: {e}')
        return jsonify({'success': False, 'message': 'サーバーエラーが発生しました。'}), 500
    finally:
        if 'db' in locals():
            db.close()

@csrf.exempt  # ← CSRF保護をこのエンドポイントだけ無効化
@app.route('/api/logout', methods=['POST'])
@login_required
def logout():
    user_email = current_user.email
    logout_user()
    session.pop('user_id', None)
    app.logger.info(f'✅ Logout successful: {user_email}')
    return jsonify({'success': True})

@app.route('/api/session', methods=['GET'])
def session_info():
    """セッション状態とユーザー情報を返す（未ログイン時は authenticated=False）"""
    if current_user.is_authenticated:
        user_data = {
            'id': current_user.id,
            'email': current_user.email,
            'role': current_user.role,
            'employee_id': current_user.employee_id
        }
        logging.debug(f'🧪 /api/session user_data: {user_data}')
        return jsonify({
            'success': True,
            'authenticated': True,
            'user': user_data
        })
    else:
        logging.info('🔵 No active session')
        return jsonify({
            'success': True,
            'authenticated': False
        })


def get_employees(page=1, per_page=15, filter_name=None, filter_email=None, filter_department=None, filter_role=None, search=None, sort_by=None, sort_order='asc'):
    """社員リストを取得（ページネーション対応）"""
    db = get_db()
    try:
        cursor = db.cursor()
        query = 'SELECT * FROM employees WHERE 1=1'
        params = []
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
        logging.info(f'✅ Retrieved {len(employees)} employees, page={page}, total={total}')
        return {'success': True, 'employees': employees, 'total': total, 'pages': pages}
    except sqlite3.Error as e:
        logging.error(f'❌ Get employees error: {e}')
        return {'success': False, 'message': str(e)}
    finally:
        db.close()

@app.route('/api/employees', methods=['GET'])
@login_required
def api_get_employees():
    """社員リストを API で取得"""
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
def api_get_employee(id):
    """特定の社員情報を取得"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM employees WHERE id = ?', (id,))
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

@app.route('/api/employees/<int:employee_id>', methods=['POST'])
@csrf.exempt  # JSから送る場合は手動でCSRFトークン検証した方が安定する
def update_employee(employee_id):
    try:
        # メタタグから取得している X-CSRF-Token を検証
        csrf_token = request.headers.get('X-CSRF-Token')
        validate_csrf(csrf_token)
    except CSRFError as e:
        return jsonify(success=False, message='CSRFトークンが無効です'), 400

    data = request.form
    name = data.get('name')
    email = data.get('email')
    department = data.get('department')
    role = data.get('role')

    if not name or not email:
        return jsonify(success=False, message='名前とメールは必須です'), 400

    try:
        db = get_db()
        cursor = db.cursor()
        cursor.execute(
            'UPDATE employees SET name=?, email=?, department=?, role=? WHERE id=?',
            (name, email, department, role, employee_id)
        )
        db.commit()
        return jsonify(success=True, message='社員情報を更新しました')
    except Exception as e:
        db.rollback()
        return jsonify(success=False, message=f'更新に失敗しました: {str(e)}'), 500

@app.route('/api/employees/<int:id>', methods=['PUT'])
@login_required
@admin_required
def api_update_employee(id):
    """社員情報を更新"""
    data = request.get_json()
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            UPDATE employees SET name = ?, email = ?, department = ?, role = ?
            WHERE id = ?
        ''', (data['name'], data['email'], data['department'], data['role'], id))
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
def api_delete_employee(id):
    """社員を削除"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('DELETE FROM employees WHERE id = ?', (id,))
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


@app.route("/api/campaigns/<int:id>", methods=["DELETE"])
@login_required
def delete_campaign(id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute("DELETE FROM campaigns WHERE id = ?", (id,))
    db.commit()
    return jsonify({"success": True, "message": "キャンペーンを削除しました"})

@app.route("/api/campaigns/<int:id>", methods=["PUT"])
@login_required
def update_campaign(id):
    data = request.get_json()
    template_ids = data.get("template_ids", [])
    department = data.get("department")
    start_date = data.get("start_date")
    end_date = data.get("end_date")

    db = get_db()
    cursor = db.cursor()
    cursor.execute("""
        UPDATE campaigns
        SET template_ids = ?, department = ?, start_date = ?, end_date = ?
        WHERE id = ?
    """, (json.dumps(template_ids), department, start_date, end_date, id))
    db.commit()
    return jsonify({"success": True, "message": "キャンペーンを更新しました"})


@app.route('/api/employees/import', methods=['POST'])
@login_required
@admin_required
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

            # ✅ 管理者の organization_id を取得
            cursor.execute("SELECT organization_id FROM users WHERE id = ?", (current_user.id,))
            org = cursor.fetchone()
            if not org or org["organization_id"] is None:
                return jsonify({'success': False, 'message': '管理者に企業が紐づいていません。'}), 400
            org_id = org["organization_id"]

            for row in csv_reader:
                name = row['name']
                email = row['email']
                department = row.get('department', '')
                role = row.get('role', '社員')
                default_password = "password123"
                password_hash = generate_password_hash(default_password)

                # ✅ employees に登録（company_nameは除く）
                cursor.execute('''
                    INSERT OR REPLACE INTO employees (name, email, department, role, organization_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (name, email, department, role, org_id))

                # ✅ employee_id を取得
                cursor.execute('SELECT id FROM employees WHERE email = ?', (email,))
                employee = cursor.fetchone()
                employee_id = employee['id'] if employee else None

                # ✅ users に登録
                cursor.execute('''
                    INSERT OR REPLACE INTO users (email, role, password, employee_id, organization_id)
                    VALUES (?, ?, ?, ?, ?)
                ''', (email, role, password_hash, employee_id, org_id))

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
def api_assign_signatures():
    """部署ごとにテンプレートを社員に自動割り当て"""
    try:
        db = get_db()
        cursor = db.cursor()

        # キャンペーンごとに対象テンプレートと部署を取得
        cursor.execute("SELECT id, department FROM campaigns")
        campaigns = cursor.fetchall()

        assigned_count = 0

        for campaign in campaigns:
            campaign_id = campaign['id']
            department = campaign['department']

            # 該当キャンペーンのテンプレートIDを取得
            cursor.execute("SELECT id FROM templates WHERE campaign_id = ?", (campaign_id,))
            template_rows = cursor.fetchall()
            template_ids = [row['id'] for row in template_rows]

            # 部署に所属する社員を取得
            cursor.execute("SELECT id FROM employees WHERE department = ?", (department,))
            employee_rows = cursor.fetchall()

            for employee in employee_rows:
                employee_id = employee['id']
                for template_id in template_ids:
                    # 既に割り当て済みでなければ挿入
                    cursor.execute("""
                        SELECT 1 FROM signature_assignments
                        WHERE employee_id = ? AND template_id = ?
                    """, (employee_id, template_id))
                    exists = cursor.fetchone()

                    if not exists:
                        cursor.execute("""
                            INSERT INTO signature_assignments (employee_id, template_id)
                            VALUES (?, ?)
                        """, (employee_id, template_id))
                        assigned_count += 1
                        print(f"✅ Assigned template_id={template_id} to employee_id={employee_id}")

        db.commit()
        db.close()

        return jsonify({
            'success': True,
            'message': f'部署に応じて署名テンプレートを自動割り当てしました（合計 {assigned_count} 件）'
        })

    except Exception as e:
        db.rollback()
        logging.error(f'❌ Error during auto signature assignment: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500







@app.route('/api/templates', methods=['GET'])
@login_required
def api_get_templates():
    """テンプレートリストを取得"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM templates ORDER BY created_at DESC')
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
def api_create_template():
    """新しいテンプレートを作成（仮トラッキングリンクも処理）"""
    data = request.get_json()
    db = get_db()
    try:
        cursor = db.cursor()

        # まずテンプレートを挿入してIDを取得（仮HTMLのままでOK）
        cursor.execute('''
            INSERT INTO templates (name, html_content, text_content, banner_url)
            VALUES (?, ?, ?, ?)
        ''', (data['name'], data['html_content'], data['text_content'], data['banner_url']))
        template_id = cursor.lastrowid
        employee_id = current_user.id  # Flask-Loginの現在のユーザーID
        html = data['html_content']

        # 仮リンクを置換してtrackingテーブルにINSERT
        import re, shortuuid
        def replace_tracking(match):
            link_text = match.group(1)
            track_id = shortuuid.uuid()
            url = f"http://localhost:5000/api/click/{track_id}"
            cursor.execute('''
                INSERT INTO tracking (track_id, url, template_id, employee_id)
                VALUES (?, ?, ?, ?)
            ''', (track_id, link_text, template_id, employee_id))
            return f'<a href="{url}" target="_blank">{link_text}</a>'

        pattern = r'<a href="\{\{tracking_link_temp_\d+\}\}" target="_blank">(.*?)<\/a>'
        updated_html = re.sub(pattern, replace_tracking, html)

        # HTMLを更新
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
def api_get_template(id):
    """特定のテンプレートを取得"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM templates WHERE id = ?', (id,))
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
def api_update_template(id):
    """テンプレートを更新"""
    data = request.get_json()
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            UPDATE templates SET name = ?, html_content = ?, text_content = ?, banner_url = ?
            WHERE id = ?
        ''', (data['name'], data['html_content'], data['text_content'], data['banner_url'], id))
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
def api_delete_template(id):
    """テンプレートを削除し、キャンペーンの template_ids からも除外"""
    db = get_db()
    try:
        cursor = db.cursor()

        # 1. templates テーブルから削除
        cursor.execute('DELETE FROM templates WHERE id = ?', (id,))
        if cursor.rowcount == 0:
            logging.warning(f'⚠️ Template not found: id={id}')
            return jsonify({'success': False, 'message': 'テンプレートが見つかりません。'}), 404

        # 2. campaigns テーブルの template_ids を更新
        cursor.execute('SELECT id, template_ids FROM campaigns')
        for row in cursor.fetchall():
            cid = row['id']
            try:
                tids = json.loads(row['template_ids'] or "[]")
            except Exception:
                tids = []

            updated_tids = [tid for tid in tids if tid != id]
            if tids != updated_tids:
                cursor.execute(
                    'UPDATE campaigns SET template_ids = ? WHERE id = ?',
                    (json.dumps(updated_tids), cid)
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
def api_get_campaigns():
    """キャンペーン一覧（テンプレート名付き）"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM campaigns')
        campaigns = cursor.fetchall()

        # id: name のテンプレート辞書（整数キー）
        cursor.execute('SELECT id, name FROM templates')
        templates = {int(row['id']): row['name'] for row in cursor.fetchall()}

        result = []
        for c in campaigns:
            try:
                ids = json.loads(c['template_ids'] or '[]')
                ids = [int(tid) for tid in ids]  # ← ここが重要！！
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

        return jsonify(result)
    except Exception as e:
        logging.error(f'❌ Failed to load campaigns: {e}')
        return jsonify({'success': False, 'message': 'キャンペーン取得に失敗'}), 500
    finally:
        db.close()




@app.route('/api/check_track_exists/<track_id>')
def check_track_exists(track_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT url FROM tracking WHERE track_id = ?', (track_id,))
        row = cursor.fetchone()

        # row が None でなければ存在すると判断
        exists = row is not None and bool(row[0])
        return jsonify({'exists': exists}), 200
    except Exception as e:
        print(f'❌ DBエラー: {e}')
        return jsonify({'exists': False, 'error': 'DBエラー'}), 500
    finally:
        db.close()






@app.route('/api/campaigns', methods=['POST'])
@login_required
@admin_required
def api_create_campaign():
    """新しいキャンペーンを作成し、署名を従業員に割り当て"""
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

        # キャンペーン作成
        cursor.execute('''
            INSERT INTO campaigns (template_ids, department, start_date, end_date)
            VALUES (?, ?, ?, ?)
        ''', (json.dumps(template_ids), department, start_date, end_date))
        campaign_id = cursor.lastrowid

        # テンプレートに campaign_id を反映
        for tid in template_ids:
            cursor.execute('UPDATE templates SET campaign_id = ? WHERE id = ?', (campaign_id, tid))

        # 🔽 部署の従業員を取得し、全員に割り当てを作成（applied_at 付き）
        cursor.execute("SELECT id FROM employees WHERE department = ?", (department,))
        employees = cursor.fetchall()
        for emp in employees:
            emp_id = emp['id']
            for tid in template_ids:
                cursor.execute('''
                    INSERT INTO signature_assignments (employee_id, template_id, applied_at)
                    VALUES (?, ?, datetime('now'))
                ''', (emp_id, tid))

        db.commit()
        logging.info('✅ Campaign, templates, and assignments updated')
        return jsonify({'success': True, 'message': 'キャンペーンが作成され、署名が部署の従業員に割り当てられました。'})
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f'❌ Create campaign error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()



@app.route('/api/departments', methods=['GET'])
@login_required
def api_get_departments():
    """部署リストを取得"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT DISTINCT department FROM employees WHERE department IS NOT NULL')
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
def api_get_signature_history():
    """署名履歴を取得"""
    db = get_db()
    try:
        cursor = db.cursor()
        query = '''
            SELECT sh.*, e.name as employee_name, t.name as template_name
            FROM signature_history sh
            JOIN employees e ON sh.employee_id = e.id
            JOIN templates t ON sh.template_id = t.id
            WHERE 1=1
        '''
        params = []
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

@app.route('/api/signature', methods=['GET'])
@login_required
def get_signature():
    app.logger.warning('⚠️ Deprecated endpoint /api/signature called, using /api/employee/signature logic')
    try:
        return get_employee_signature()
    except Exception as e:
        app.logger.error(f'❌ Error in /api/signature: {str(e)}')
        return jsonify({
            'success': False,
            'message': f'サーバーエラー: {str(e)}'
        }), 500

@app.route('/click/<track_id>')
def track_click(track_id):
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('UPDATE tracking SET clicks = clicks + 1 WHERE track_id = ?', (track_id,))
        cursor.execute('SELECT url FROM tracking WHERE track_id = ?', (track_id,))
        row = cursor.fetchone()
        if row:
            return redirect(row['url'])
        else:
            return 'Invalid tracking ID', 404
    except Exception as e:
        logging.exception(f'❌ Click tracking failed: {e}')
        return 'Server error', 500
    finally:
        db.close()

@app.route('/admin/create')
def admin_create_page():
    return render_template('admin_create.html')




@app.route('/api/check_admin_password', methods=['POST'])
def check_admin_password():
    data = request.get_json()
    entered = data.get('password')
    expected = os.getenv('ADMIN_CREATE_PASSWORD')
    if entered == expected:
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'message': 'パスワードが間違っています'}), 401

@app.route('/api/get_admin_key')
def get_admin_key():
    from dotenv import load_dotenv
    load_dotenv()
    admin_key = os.getenv("ADMIN_CREATE_PASSWORD", "")
    return jsonify({'key': admin_key})


@app.route('/api/companies', methods=['GET'])
def get_company_list():  # ← 別名にする
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("""
            SELECT o.id, o.name AS company_name,
                   COUNT(e.id) AS employee_count,
                   (SELECT u.email FROM users u WHERE u.organization_id = o.id AND u.role = 'admin' LIMIT 1) AS admin_email
            FROM organizations o
            LEFT JOIN employees e ON e.organization_id = o.id
            GROUP BY o.id
        """)
        results = cursor.fetchall()
        return jsonify([dict(row) for row in results])
    except Exception as e:
        import logging
        logging.exception("❌ company API error:")
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()





@app.route('/api/create_admin', methods=['POST'])
@csrf.exempt
def create_admin():
    try:
        data = request.get_json()
        logging.info(f"📦 create_admin payload: {data}")

        email = data.get('email')
        password = data.get('password')
        company_name = data.get('company_name')

        if not email or not password or not company_name:
            return jsonify({'success': False, 'message': 'すべての項目を入力してください'}), 400

        db = get_db()
        cursor = db.cursor()

        # 組織が存在するか確認、なければ作成
        cursor.execute("SELECT id FROM organizations WHERE name = ?", (company_name,))
        org = cursor.fetchone()
        if org:
            org_id = org['id']
        else:
            cursor.execute("INSERT INTO organizations (name) VALUES (?)", (company_name,))
            org_id = cursor.lastrowid

        # ユーザーがすでに存在するかチェック
        cursor.execute("SELECT id FROM users WHERE email = ?", (email,))
        if cursor.fetchone():
            return jsonify({'success': False, 'message': 'このメールアドレスは既に登録されています'}), 400

        # employees にも admin として登録（存在しなければ）
        cursor.execute('''
            INSERT OR IGNORE INTO employees (name, email, department, role, organization_id)
            VALUES (?, ?, ?, ?, ?)
        ''', ('管理者', email, '', 'admin', org_id))

        # employee_id を取得
        cursor.execute("SELECT id FROM employees WHERE email = ?", (email,))
        employee_id = cursor.fetchone()['id']

        # users テーブルに登録（employee_id付き）
        hashed_pw = generate_password_hash(password)
        cursor.execute("""
            INSERT INTO users (email, password, role, employee_id, organization_id)
            VALUES (?, ?, 'admin', ?, ?)
        """, (email, hashed_pw, employee_id, org_id))

        db.commit()
        return jsonify({'success': True, 'message': '管理者アカウントを作成しました'})

    except Exception as e:
        logging.exception("❌ create_admin error:")
        db.rollback()
        return jsonify({'success': False, 'message': f'作成エラー: {e}'}), 500
    finally:
        db.close()


csrf.exempt(create_admin)

@app.route('/api/companies', methods=['GET'])
@login_required
def get_companies():
    if current_user.role != 'admin':
        return jsonify({'success': False, 'message': '権限がありません'}), 403

    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute("""
            SELECT
                o.id,
                o.name AS company_name,
                (
                    SELECT COUNT(*) FROM users u
                    WHERE u.organization_id = o.id AND u.role = 'employee'
                ) AS employee_count,
                (
                    SELECT u2.email FROM users u2
                    WHERE u2.organization_id = o.id AND u2.role = 'admin'
                    LIMIT 1
                ) AS admin_email
            FROM organizations o
        """)
        results = cursor.fetchall()
        return jsonify([
            {
                'id': row['id'],
                'company_name': row['company_name'],
                'employee_count': row['employee_count'],
                'admin_email': row['admin_email']
            }
            for row in results
        ])
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()




@app.route('/api/employee/signature', methods=['GET'])
@login_required
def get_employee_signature():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # STEP 1: ログイン中の社員ID確認
        employee_id = current_user.employee_id or current_user.id
        app.logger.debug(f'👤 employee_id: {employee_id}')

        # STEP 2: 割り当てられたテンプレート取得
        cursor.execute("""
            SELECT t.id AS template_id, t.html_content, t.text_content, t.banner_url
            FROM templates t
            JOIN signature_assignments sa ON t.id = sa.template_id
            WHERE sa.employee_id = ?
            ORDER BY COALESCE(sa.applied_at, sa.assigned_at) DESC
            LIMIT 1
        """, (employee_id,))
        signature = cursor.fetchone()

        if not signature:
            app.logger.warning(f'⚠️ No signature found for employee_id: {employee_id}')
            return jsonify({'success': False, 'message': '署名が見つかりませんでした'}), 404

        app.logger.debug(f'📝 Signature template found: {signature["template_id"]}')

        # STEP 3: 該当社員情報を取得
        cursor.execute("SELECT * FROM employees WHERE id = ?", (employee_id,))
        employee = cursor.fetchone()

        if not employee:
            app.logger.warning(f'❌ No employee record found for ID: {employee_id}')
            return jsonify({'success': False, 'message': '社員情報が見つかりませんでした'}), 404

        # ✅ 会社名を取得
        cursor.execute("SELECT name FROM organizations WHERE id = ?", (employee["organization_id"],))
        org = cursor.fetchone()
        company_name = org["name"] if org else "未登録"

        # STEP 4: 埋め込み変数の中身確認
        variables = {
            "name": employee["name"],
            "email": employee["email"],
            "role": employee["role"],
            "department": employee["department"],
            "company": company_name,
            "phone": employee["phone"] if employee["phone"] else "未登録",
            "address": employee["address"] if employee["address"] else "未登録",
            "website": employee["website"] if employee["website"] else "未登録",
            "linkedin": employee["linkedin"] if employee["linkedin"] else "未登録",
            "banner_url": signature["banner_url"] if signature["banner_url"] else "未登録"
        }

        app.logger.debug(f'📦 Template variables: {variables}')

        # STEP 5: HTML差し込み前後の内容確認
        rendered_html = render_signature_template(signature['html_content'], variables)
        app.logger.debug(f'🧾 Rendered HTML: {rendered_html}')

        final_html = replace_links_with_tracking(rendered_html, employee["id"], signature["template_id"])
        app.logger.debug(f'✅ Final HTML with tracking: {final_html}')

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
def apply_signature():
    data = request.get_json()
    template_id = data.get('template_id')

    if not template_id:
        return jsonify({'success': False, 'message': 'テンプレートIDが必要です'}), 400

    db = get_db()
    try:
        cursor = db.cursor()

        # テンプレート取得
        cursor.execute('SELECT * FROM templates WHERE id = ?', (template_id,))
        template = cursor.fetchone()
        if not template:
            return jsonify({'success': False, 'message': 'テンプレートが存在しません'}), 404

        # 社員取得
        cursor.execute('SELECT * FROM employees WHERE id = ?', (current_user.employee_id,))
        employee = cursor.fetchone()
        if not employee:
            return jsonify({'success': False, 'message': '社員情報が見つかりません'}), 404

        # 会社名取得
        cursor.execute('SELECT name FROM organizations WHERE id = ?', (employee['organization_id'],))
        org = cursor.fetchone()
        company_name = org['name'] if org else '未登録'

        # 埋め込み変数
        variables = {
            "name": employee["name"],
            "email": employee["email"],
            "role": employee["role"],
            "department": employee["department"],
            "company": company_name,
            "phone": employee["phone"] or "未登録",
            "address": employee["address"] or "未登録",
            "website": employee["website"] or "未登録",
            "linkedin": employee["linkedin"] or "未登録",
            "banner_url": template["banner_url"] or ""
        }

        html_filled = render_signature_template(template["html_content"], variables)
        html_final = replace_links_with_tracking(html_filled, employee["id"], template_id)

        # 履歴保存
        cursor.execute('INSERT INTO signature_history (employee_id, template_id) VALUES (?, ?)', (employee["id"], template_id))
        db.commit()

        return jsonify({'success': True, 'signature_html': html_final})

    except Exception as e:
        db.rollback()
        logging.error(f'❌ Signature apply error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()







@app.route('/api/signature')
@login_required
def deprecated_signature():
    import traceback
    try:
        logging.warning("⚠️ Deprecated endpoint /api/signature called, proxying to /api/employee/signature")
        result = get_employee_signature()
        logging.debug("✅ get_employee_signature() returned: %s", result)
        return result
    except Exception as e:
        tb = traceback.format_exc()
        print("🔥 ERROR in /api/signature:\n", tb)
        logging.error("🔥 Exception in /api/signature: %s", str(e))
        logging.error("🔥 Traceback:\n%s", tb)
        return jsonify({'success': False, 'message': f"Internal Error: {str(e)}"}), 500

@app.route('/api/render_signature', methods=['POST'])
@login_required
@employee_required
def render_signature_api():
    try:
        data = request.get_json()
        template_id = data.get('template_id')
        if not template_id:
            return jsonify({'success': False, 'message': 'テンプレートIDが必要です'}), 400

        db = get_db()
        cursor = db.cursor()

        cursor.execute('SELECT html_content FROM templates WHERE id = ?', (template_id,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'message': 'テンプレートが見つかりません'}), 404

        template_html = row['html_content']

        cursor.execute('SELECT * FROM employees WHERE id = ?', (current_user.employee_id,))
        employee = cursor.fetchone()
        if not employee:
            return jsonify({'success': False, 'message': '社員情報が見つかりません'}), 404

        # 会社名取得
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






@app.route('/api/generate_track', methods=['POST'])
@login_required
def generate_track():
    try:
        data = request.get_json()
        url = data.get('url')
        template_id = data.get('templateId') or data.get('template_id')
        employee_id = data.get('employeeId') or data.get('employee_id')

        logging.info(f'📥 tracking生成リクエスト受信: url={url}, template_id={template_id}, employee_id={employee_id}')

        if not url or not employee_id:
            return jsonify({'success': False, 'message': 'URLとemployee_idは必須です'}), 400

        track_id = shortuuid.uuid()
        db = get_db()
        cursor = db.cursor()

        cursor.execute('''
            INSERT INTO tracking (track_id, url, template_id, employee_id, clicks, created_at)
            VALUES (?, ?, ?, ?, 0, CURRENT_TIMESTAMP)
        ''', (track_id, url, template_id, employee_id))

        db.commit()
        # 絶対URLを生成
        track_url = url_for('api_track_click', track_id=track_id, _external=True)
        logging.info(f'✅ tracking生成成功: track_id={track_id}, url={url}, track_url={track_url}')
        return jsonify({'success': True, 'track_url': track_url})
    except Exception as e:
        logging.exception('❌ tracking生成中にエラー発生')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()



from flask import make_response, redirect, request, jsonify
from datetime import datetime
import sqlite3
import logging

@app.route('/api/click/<track_id>', methods=['GET'])
def api_track_click(track_id):
    db = get_db()
    db.row_factory = sqlite3.Row
    try:
        cursor = db.cursor()

        # 該当トラッキング情報取得
        cursor.execute('SELECT * FROM tracking WHERE track_id = ?', (track_id,))
        track = cursor.fetchone()
        if not track:
            logging.warning(f'⚠️ トラッキングIDが見つかりません: {track_id}')
            return jsonify({'success': False, 'message': 'トラッキングが見つかりません'}), 404

        ip = request.remote_addr
        ua = request.headers.get('User-Agent', 'unknown')
        now = datetime.utcnow()
        now_str = now.isoformat()

        # Cookie チェック
        cookie_key = f"track_{track_id}"
        clicked_cookie = request.cookies.get(cookie_key)
        logging.info(f'🧪 Click attempt: track_id={track_id}, ip={ip}, ua={ua}, cookie={clicked_cookie}')

        if clicked_cookie:
            logging.info(f'🍪 Cookie blocked: {track_id}')
            return redirect(track['url'])

        # IP アクセス間隔チェック（10秒以内の重複クリックを排除）
        cursor.execute('''
            SELECT created_at FROM analytics
            WHERE track_id = ? AND ip = ?
            ORDER BY created_at DESC LIMIT 1
        ''', (track_id, ip))
        row = cursor.fetchone()
        if row and row['created_at']:
            last_click = datetime.fromisoformat(row['created_at']) if isinstance(row['created_at'], str) else row['created_at']
            if (now - last_click).total_seconds() < 10:
                logging.info(f'🛑 IP timing blocked (10秒以内): {track_id}')
                return redirect(track['url'])

        # Cookie を設定し、クリックカウントと analytics に記録
        resp = make_response(redirect(track['url']))
        resp.set_cookie(cookie_key, 'clicked', max_age=60, httponly=True)

        cursor.execute('UPDATE tracking SET clicks = clicks + 1 WHERE track_id = ?', (track_id,))
        cursor.execute('''
            INSERT INTO analytics (track_id, template_id, employee_id, ip, user_agent, created_at)
            SELECT track_id, template_id, employee_id, ?, ?, ?
            FROM tracking
            WHERE track_id = ?
        ''', (ip, ua, now_str, track_id))

        db.commit()
        logging.info(f'✅ Click tracked: {track_id} (cookie + ip checked)')
        return resp

    except Exception as e:
        logging.error(f'❌ Error tracking click: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()


@app.route('/api/save_template', methods=['POST'])
@login_required
def save_template():
    data = request.get_json()
    html = data.get('html', '')
    
    if '{{tracking_link_temp_' in html:
        return jsonify({'success': False, 'message': '一時リンクが残っています。コピー前に必ず置換してください。'}), 400






@app.route('/debug/employee-clicks')
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
            GROUP BY e.id
        ''')
        rows = cursor.fetchall()
        output = '<h2>社員ごとのクリック数</h2><table border="1"><tr><th>ID</th><th>名前</th><th>クリック数</th></tr>'
        for row in rows:
            output += f"<tr><td>{row['employee_id']}</td><td>{row['employee_name']}</td><td>{row['clicks']}</td></tr>"
        output += '</table>'
        return output
    except Exception as e:
        return f'<p>エラー: {e}</p>'









@app.route('/api/analytics', methods=['GET'])
@login_required
def api_get_analytics():
    db = get_db()
    try:
        cursor = db.cursor()

        # 🔍 クエリパラメータ確認ログ
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        track_id = request.args.get('track_id')
        logging.info(f'🔎 API params received: start_date={start_date}, end_date={end_date}, track_id={track_id}')

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
            WHERE 1=1
        '''
        params = []

        if start_date:
            query += ' AND date(a.clicked_at) >= date(?)'
            params.append(start_date)
        if end_date:
            query += ' AND date(a.clicked_at) <= date(?)'
            params.append(end_date)
        if track_id:
            query += ' AND a.track_id = ?'
            params.append(track_id)

        logging.info(f'🛠️ Executing query: {query}')
        logging.info(f'🧾 With params: {params}')

        cursor.execute(query, params)
        analytics = [dict(row) for row in cursor.fetchall()]
        logging.info(f'✅ Retrieved {len(analytics)} analytics records after filtering')
        return jsonify(analytics)
    except sqlite3.Error as e:
        logging.error(f'❌ Get analytics error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()






@app.route("/api/employee-analytics")
@login_required
def employee_analytics():
    try:
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        logger.info("🧠 /api/employee-analytics start=%s end=%s", start_date, end_date)
        if not start_date or not end_date:
            return jsonify([])
        db = get_db()
        cursor = db.cursor()
        query = """
            SELECT e.id AS employee_id,
                   e.name AS employee_name,
                   e.department AS department,
                   COUNT(*) AS clicks
            FROM analytics a
            JOIN employees e ON a.employee_id = e.id
            WHERE DATE(datetime(clicked_at, '+9 hours')) BETWEEN DATE(?) AND DATE(?)
            GROUP BY e.id
        """
        cursor.execute(query, (start_date, end_date))
        rows = cursor.fetchall()
        result = [{
            "employee_id": row["employee_id"],
            "employee_name": row["employee_name"],
            "department": row["department"],
            "clicks": row["clicks"]
        } for row in rows]
        logger.info("✅ /api/employee-analytics returned %d rows", len(result))
        return jsonify(result)
    except Exception as e:
        logger.exception("❌ /api/employee-analytics failed:")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/analytics/department")
@login_required
def department_analytics():
    try:
        start_date = request.args.get("start_date")
        end_date = request.args.get("end_date")
        logger.info("🧠 /api/analytics/department start=%s end=%s", start_date, end_date)
        if not start_date or not end_date:
            return jsonify([])
        db = get_db()
        cursor = db.cursor()
        query = """
            SELECT e.department AS department,
                   COUNT(*) AS clicks
            FROM analytics a
            JOIN employees e ON a.employee_id = e.id
            WHERE DATE(datetime(clicked_at, '+9 hours')) BETWEEN DATE(?) AND DATE(?)
            GROUP BY e.department
        """
        cursor.execute(query, (start_date, end_date))
        rows = cursor.fetchall()
        result = [{
            "department": row["department"],
            "clicks": row["clicks"]
        } for row in rows]
        logger.info("✅ /api/analytics/department returned %d rows", len(result))
        return jsonify(result)
    except Exception as e:
        logger.exception("❌ /api/analytics/department failed:")
        return jsonify({"error": "Internal server error"}), 500







@app.route("/template_editor/<int:template_id>")
@login_required
def template_editor(template_id):
    db = get_db()
    try:
        template = db.execute("SELECT * FROM templates WHERE id = ?", (template_id,)).fetchone()
        if not template:
            return "テンプレートが見つかりません", 404
        print("🛠 渡すtemplateの中身:", dict(template))  # ← 追加
        return render_template("template_editor.html", template=dict(template), user_role=current_user.role)
    finally:
        db.close()



@app.route("/template_editor")
@login_required
def new_template():
    empty_template = {
        "id": "",
        "name": "",
        "html_content": "",
        "text_content": "",
        "banner_url": ""
    }
    return render_template(
        "template_editor.html",
        template=empty_template,
        user_role=current_user.role
    )



@app.route('/api/analytics/abtest_summary', methods=['GET'])
@login_required
def api_get_abtest_summary():
    db = get_db()
    try:
        cursor = db.cursor()
        query = '''
            SELECT
                t.id AS template_id,
                t.name AS template_name,
                COUNT(a.id) AS clicks,
                COUNT(tr.id) AS impressions,
                ROUND(CAST(COUNT(a.id) AS FLOAT) / NULLIF(COUNT(tr.id), 0) * 100, 1) AS ctr
            FROM templates t
            LEFT JOIN tracking tr ON tr.template_id = t.id
            LEFT JOIN analytics a ON a.track_id = tr.track_id
            GROUP BY t.id, t.name
            ORDER BY clicks DESC;
        '''
        cursor.execute(query)
        rows = [dict(row) for row in cursor.fetchall()]
        return jsonify({'success': True, 'data': rows})
    except Exception as e:
        logging.error(f'❌ Error in abtest summary: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()



@app.route('/api/analytics/department', methods=['GET'])
@login_required
def api_get_department_analytics():
    """部署ごとのアナリティクスを取得"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            SELECT e.department, COUNT(a.id) as clicks
            FROM analytics a
            LEFT JOIN employees e ON a.employee_id = e.id
            GROUP BY e.department
        ''')
        data = [dict(row) for row in cursor.fetchall()]
        logging.info(f'✅ Retrieved {len(data)} department analytics records')
        return jsonify({'success': True, 'data': data})
    except sqlite3.Error as e:
        logging.error(f'❌ Get department analytics error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()


@app.route('/api/timeband', methods=['GET'])
@login_required
def api_get_timeband():
    db = get_db()
    try:
        cursor = db.cursor()
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        query = '''
            SELECT strftime('%H:00', datetime(clicked_at, '+9 hours')) as timeband, COUNT(*) as clicks
            FROM analytics
            WHERE 1=1
        '''
        params = []
        
        if start_date:
            query += " AND DATE(datetime(clicked_at, '+9 hours')) >= DATE(?)"
            params.append(start_date)
        if end_date:
            query += " AND DATE(datetime(clicked_at, '+9 hours')) <= DATE(?)"
            params.append(end_date)
        
        query += ' GROUP BY timeband'
        
        cursor.execute(query, params)
        timebands = {row['timeband']: row['clicks'] for row in cursor.fetchall()}
        logging.info(f'✅ Retrieved timeband analytics with {len(timebands)} records')
        return jsonify({'timebands': timebands})
    except sqlite3.Error as e:
        logging.error(f'❌ Get timeband error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()


@app.route('/api/register', methods=['POST'])
def register():
    """新しいユーザーを登録"""
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'employee')
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            logging.warning(f'⚠️ Email already registered: {email}')
            return jsonify({'success': False, 'message': 'メールアドレスは既に登録されています。'}), 400
        hashed_password = generate_password_hash(password)
        cursor.execute('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', (email, hashed_password, role))
        db.commit()
        logging.info(f'✅ User registered: {email}')
        return jsonify({'success': True, 'message': 'ユーザーが登録されました。'})
    except sqlite3.Error as e:
        db.rollback()
        logging.error(f'❌ Register error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        db.close()

@app.route('/api/statistics', methods=['GET'])
@login_required
def api_get_statistics():
    """統計データを取得"""
    db = get_db()
    try:
        cursor = db.cursor()
        cursor.execute('''
            SELECT t.id as tid, 
                   (SELECT COUNT(*) FROM analytics a2 WHERE a2.track_id = t.track_id) as clicks,
                   e.name as employee_name
            FROM tracking t
            LEFT JOIN employees e ON t.employee_id = e.id
        ''')
        data = [dict(row) for row in cursor.fetchall()]
        logging.info(f'✅ Retrieved statistics: {len(data)} records')
        return jsonify(data)
    except sqlite3.Error as e:
        logging.error(f'❌ Get statistics error: {e}')
        return jsonify({'success': False, 'message': str(e)}), 500
    finally:
        cursor.close()
        db.close()
if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run(debug=True)
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=10000, debug=True)
