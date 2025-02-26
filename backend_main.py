from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'  # For development; use PostgreSQL/MySQL for production
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = 'your_secret_key_here'

db = SQLAlchemy(app)
jwt = JWTManager(app)

# ---------------------- MODELS ---------------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    bio = db.Column(db.String(500), default="")  # Only text allowed
    earnings = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    posts = db.relationship('Post', backref='user', lazy=True)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # Text-only post
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    likes = db.Column(db.Integer, default=0)
    dislikes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='post', lazy=True)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)  # Text-only comment
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

# ---------------------- DATABASE INIT ---------------------- #
@app.before_first_request
def create_tables():
    db.create_all()

# ---------------------- AUTHENTICATION ROUTES ---------------------- #
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    if User.query.filter_by(email=email).first() or User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, email=email, password_hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    user = User.query.filter_by(email=email).first()
    if not user or not check_password_hash(user.password_hash, password):
        return jsonify({'message': 'Invalid credentials'}), 401
    token = create_access_token(identity=user.id, expires_delta=datetime.timedelta(days=7))
    return jsonify({'token': token, 'user': {'username': user.username, 'bio': user.bio, 'earnings': user.earnings}})

@app.route('/profile', methods=['GET'])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    return jsonify({'username': user.username, 'email': user.email, 'bio': user.bio, 'earnings': user.earnings})

# ---------------------- POSTS & INTERACTIONS ---------------------- #
@app.route('/posts', methods=['POST'])
@jwt_required()
def create_post():
    user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({'message': 'Content is required'}), 400
    new_post = Post(content=content, user_id=user_id)
    db.session.add(new_post)
    db.session.commit()
    return jsonify({'message': 'Post created successfully'}), 201

@app.route('/posts', methods=['GET'])
def get_posts():
    posts = Post.query.order_by(Post.created_at.desc()).all()
    output = []
    for post in posts:
        output.append({
            'id': post.id,
            'content': post.content,
            'created_at': post.created_at,
            'username': post.user.username,
            'likes': post.likes,
            'dislikes': post.dislikes
        })
    return jsonify({'posts': output})

@app.route('/posts/<int:post_id>/like', methods=['POST'])
@jwt_required()
def like_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.likes += 1
    db.session.commit()
    return jsonify({'message': 'Post liked', 'likes': post.likes})

@app.route('/posts/<int:post_id>/dislike', methods=['POST'])
@jwt_required()
def dislike_post(post_id):
    post = Post.query.get_or_404(post_id)
    post.dislikes += 1
    db.session.commit()
    return jsonify({'message': 'Post disliked', 'dislikes': post.dislikes})

@app.route('/posts/<int:post_id>/comments', methods=['POST'])
@jwt_required()
def comment_post(post_id):
    user_id = get_jwt_identity()
    data = request.get_json()
    content = data.get('content')
    if not content:
        return jsonify({'message': 'Comment content is required'}), 400
    new_comment = Comment(content=content, user_id=user_id, post_id=post_id)
    db.session.add(new_comment)
    db.session.commit()
    return jsonify({'message': 'Comment added successfully'}), 201

@app.route('/posts/<int:post_id>/comments', methods=['GET'])
def get_comments(post_id):
    comments = Comment.query.filter_by(post_id=post_id).order_by(Comment.created_at.asc()).all()
    output = []
    for comment in comments:
        user = User.query.get(comment.user_id)
        output.append({
            'id': comment.id,
            'content': comment.content,
            'username': user.username if user else 'Unknown',
            'created_at': comment.created_at
        })
    return jsonify({'comments': output})

if __name__ == '__main__':
    app.run(debug=True)
