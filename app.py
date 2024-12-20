from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'default-secret-key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///database.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# 用户模型
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    scores = db.relationship('Score', backref='user', lazy=True)

# 分数模型  
class Score(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    score = db.Column(db.Integer, nullable=False)
    date = db.Column(db.DateTime, nullable=False)
    duration = db.Column(db.Integer, nullable=True)  # 游戏时长(秒)
    lives = db.Column(db.Integer, nullable=True)  # 剩余生命
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        return redirect(url_for('login'))
    session['username'] = user.username
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if not user:
            return render_template('login.html', error="该用户未注册", top_scores=get_top_scores())
        elif not check_password_hash(user.password, password):
            return render_template('login.html', error="密码错误", top_scores=get_top_scores())
        
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('index'))
        
    # 获取排行榜数据
    top_scores = get_top_scores()
    return render_template('login.html', top_scores=top_scores)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template('register.html', error="两次输入的密码不一致", top_scores=get_top_scores())
            
        if User.query.filter_by(username=username).first():
            return render_template('register.html', error="用户名已存在", top_scores=get_top_scores())
            
        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
        
    return render_template('register.html', top_scores=get_top_scores())

def get_top_scores():
    try:
        # 首先获取每个用户的最高分记录
        subquery = db.session.query(
            User.username,
            Score.score,
            Score.duration,
            Score.lives,
            db.func.row_number().over(
                partition_by=User.username,
                order_by=[
                    Score.score.desc(),
                    Score.lives.desc(),
                    Score.duration.asc()
                ]
            ).label('rn')
        ).join(Score).subquery()
        
        # 然后只选择每个用户的最佳记录
        return db.session.query(
            subquery.c.username,
            subquery.c.score,
            subquery.c.duration,
            subquery.c.lives
        ).filter(subquery.c.rn == 1)\
        .order_by(
            subquery.c.score.desc(),
            subquery.c.lives.desc(),
            subquery.c.duration.asc()
        )\
        .limit(10).all()
    except:
        return []

@app.route('/profile')
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
        
    user = User.query.get(session['user_id'])
    scores = Score.query.filter_by(user_id=user.id).order_by(Score.score.desc()).limit(10).all()
    
    return render_template('profile.html', user=user, scores=scores)

@app.route('/save_score', methods=['POST'])
def save_score():
    if 'user_id' not in session:
        return jsonify({'error': 'Not logged in'}), 401
        
    data = request.get_json()
    score = data.get('score')
    duration = data.get('duration')
    lives = data.get('lives')
    
    if score is None:
        return jsonify({'error': 'No score provided'}), 400
        
    new_score = Score(
        score=score,
        date=datetime.datetime.now(),
        duration=duration,
        lives=lives,
        user_id=session['user_id']
    )
    
    db.session.add(new_score)
    db.session.commit()
    
    return jsonify({'message': 'Score saved successfully'})

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/reset_db')
def reset_db():
    with app.app_context():
        db.drop_all()
        db.create_all()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True) 