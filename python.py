from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import re

# 初始化Flask应用和数据库
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'  # 生产环境请使用强密钥
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'  # 使用SQLite数据库，文件名为users.db
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 定义用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)  # 用户名，唯一
    password_hash = db.Column(db.String(200), nullable=False)  # 密码哈希值

    def set_password(self, password):
        """设置密码，自动加密"""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """验证密码"""
        return check_password_hash(self.password_hash, password)

# 创建数据库表（首次运行时创建）
with app.app_context():
    db.create_all()

# 辅助函数：验证用户名和密码格式
def validate_username(username):
    """用户名验证：长度3-20位，只允许字母、数字、下划线"""
    if re.match(r'^[a-zA-Z0-9_]{3,20}$', username):
        return True
    return False

def validate_password(password):
    """密码验证：长度至少6位，包含字母和数字"""
    if len(password) < 6:
        return False
    if not re.search(r'[a-zA-Z]', password) or not re.search(r'\d', password):
        return False
    return True

# 路由：用户登录
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': '缺少用户名或密码字段'}), 400

    username = data['username'].strip()
    password = data['password'].strip()
    
    # 查找用户
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        return jsonify({
            'message': '登录成功',
            'user': {'id': user.id, 'username': user.username}
        }), 200
    else:
        return jsonify({'error': '用户名或密码错误'}), 401

# 路由：用户注册
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or 'username' not in data or 'password' not in data:
        return jsonify({'error': '缺少用户名或密码字段'}), 400

    username = data['username'].strip()
    password = data['password'].strip()

    # 验证格式
    if not validate_username(username):
        return jsonify({'error': '用户名格式无效：长度3-20位，只允许字母、数字、下划线'}), 400
    if not validate_password(password):
        return jsonify({'error': '密码格式无效：至少6位，需包含字母和数字'}), 400

    # 检查用户名是否已存在
    if User.query.filter_by(username=username).first():
        return jsonify({'error': '用户名已存在'}), 409

    # 创建新用户
    try:
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()
        return jsonify({
            'message': '注册成功',
            'user': {'id': new_user.id, 'username': new_user.username}
        }), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': '注册失败，服务器错误'}), 500

# 路由：忘记密码（简化版：仅验证用户名存在性）
@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    if not data or 'username' not in data:
        return jsonify({'error': '缺少用户名字段'}), 400

    username = data['username'].strip()
    user = User.query.filter_by(username=username).first()
    
    if user:
        # 实际应用中应发送密码重置邮件或链接，这里仅返回提示
        return jsonify({'message': '用户名验证成功，请检查注册邮箱以重置密码'}), 200
    else:
        return jsonify({'error': '用户名不存在'}), 404

# 路由：健康检查（可选）
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': '后端运行正常'}), 200

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)  # 开启调试模式，监听所有IP的5000端口
