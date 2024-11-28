from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt

app = Flask(__name__)

app.config['SECRET_KEY'] = 'thien_duong_88'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:giohai@localhost:5432/usersmanager'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt_pass = Bcrypt(app)

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    role_name = db.Column(db.String(100), unique=True, nullable=False)

class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(50), nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'), nullable=False)
    # Noi giua cac bang
    role_rls = db.relationship('Role', backref='users', lazy=True)


'''def create_admin(username, password):
    mkpw = bcrypt_pass.generate_password_hash(password).decode('utf-8')
    new_admin = Users(username=username, password=mkpw, role_id=1)
    db.session.add(new_user)
    db.session.commit()


with app.app_context():
    create_user('admin1', 'dangcapvailol')'''


@app.route('/')
def home():
    return render_template('register.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        # Kiểm tra người dùng đã tồn tại
        user_exist = Users.query.filter_by(username=username).first()
        if user_exist:
            flash('Username already exists. Please choose a different one.', 'error')
            return redirect(url_for('register'))
        
        # Kiểm tra mật khẩu và xác nhận mật khẩu
        if password != confirm_password:
            flash('Passwords do not match. Please try again.', 'error')
            return redirect(url_for('register'))

        # Mã hóa mật khẩu
        hashed_password = bcrypt_pass.generate_password_hash(password).decode('utf-8')

        # Tạo người dùng mới
        new_user = Users(username=username, password=hashed_password, role_id=2)

        # Thêm người dùng vào cơ sở dữ liệu
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))  # Redirect đến trang đăng nhập sau khi đăng ký thành công

    return render_template('register.html')  # Render form đăng ký khi là phương thức GET

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user_check = Users.query.filter_by(username=username).first()

        open_password = bcrypt_pass.check_password_hash(user_check.password, password)

        if user_check:
            if open_password:
                role_id = user_check.role_id
                if role_id == 1:
                    session['admin'] = user_check.username
                    return redirect(url_for('admindab'))
                elif role_id == 2:
                    session['user'] = user_check.username
                    return redirect(url_for('dashboard'))
            else:
                flash('Password is wrong. Please try again!', 'error')
                return redirect(url_for('login'))
        else:
            flash('User not found. Please try again!')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    user = session.get('user')
    return render_template('dashboard.html', user=user)  # Truyền biến user vào mẫu

@app.route('/admindab')
def admindab():
    admin = session.get('admin')
    return render_template('admindab.html', admin=admin)  # Truyền biến user vào mẫu

if __name__ == "__main__":
    app.run(debug=True)

