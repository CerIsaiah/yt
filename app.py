from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from googleapiclient.errors import HttpError
from google_auth_oauthlib.flow import Flow
import os
import json
import random
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your_secret_key_here')
app.permanent_session_lifetime = timedelta(days=30)

limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

COMMENTS_FILE = "user_comments.json"
CLIENT_SECRETS_FILE = "client_secret.json"  # Download this from Google Developers Console
SCOPES = ['https://www.googleapis.com/auth/youtube.force-ssl']

class YoutubeApi:
    @staticmethod
    def get_authenticated_service():
        credentials = Credentials(**session['credentials'])
        return build('youtube', 'v3', credentials=credentials)

    @staticmethod
    def make_search(query, max_results=10):
        youtube = YoutubeApi.get_authenticated_service()
        try:
            return youtube.search().list(
                q=query,
                maxResults=max_results,
                part="snippet",
                type="video"
            ).execute()
        except HttpError as e:
            print(f"An error occurred: {e}")
            return None

    @staticmethod
    def add_comment(video_id, comment):
        youtube = YoutubeApi.get_authenticated_service()
        try:
            youtube.commentThreads().insert(
                part="snippet",
                body={
                    "snippet": {
                        "videoId": video_id,
                        "topLevelComment": {
                            "snippet": {
                                "textOriginal": comment
                            }
                        }
                    }
                }
            ).execute()
            return True
        except HttpError as e:
            print(f"An error occurred: {e}")
            return False

def load_user_comments(user_id):
    if os.path.exists(COMMENTS_FILE):
        with open(COMMENTS_FILE, 'r') as file:
            all_comments = json.load(file)
            return all_comments.get(user_id, [])
    return []

def save_user_comments(user_id, comments):
    all_comments = {}
    if os.path.exists(COMMENTS_FILE):
        with open(COMMENTS_FILE, 'r') as file:
            all_comments = json.load(file)
    all_comments[user_id] = comments
    with open(COMMENTS_FILE, 'w') as file:
        json.dump(all_comments, file)

@app.before_request
def before_request():
    session.permanent = True
    if 'user_id' not in session:
        session['user_id'] = str(random.randint(1000000, 9999999))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    state = session['state']
    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)

    authorization_response = request.url
    flow.fetch_token(authorization_response=authorization_response)

    credentials = flow.credentials
    session['credentials'] = {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }
    return redirect(url_for('index'))

@app.route('/get_comments', methods=['GET'])
def get_comments():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401
    
    user_comments = load_user_comments(user_id)
    return jsonify({'comments': user_comments})

@app.route('/add_comment', methods=['POST'])
@limiter.limit("10 per minute")
def add_comment():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    new_comment = request.form.get('new_comment')
    if not new_comment:
        return jsonify({'error': 'No comment provided'}), 400

    user_comments = load_user_comments(user_id)
    user_comments.append(new_comment)
    save_user_comments(user_id, user_comments)

    return jsonify({'status': 'success', 'comment': new_comment})

@app.route('/remove_comment', methods=['POST'])
def remove_comment():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    comment_to_remove = request.form.get('comment')
    if not comment_to_remove:
        return jsonify({'error': 'No comment provided'}), 400

    user_comments = load_user_comments(user_id)
    if comment_to_remove in user_comments:
        user_comments.remove(comment_to_remove)
        save_user_comments(user_id, user_comments)
        return jsonify({'status': 'success'})
    else:
        return jsonify({'error': 'Comment not found'}), 404

@app.route('/search', methods=['POST'])
@limiter.limit("5 per minute")
def search():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))
    
    query = request.form.get('query')
    if not query:
        return jsonify({'error': 'No query provided'}), 400
    
    results = YoutubeApi.make_search(query)
    if results is None:
        return jsonify({'error': 'An error occurred while searching'}), 500
    
    return jsonify(results)

@app.route('/comment', methods=['POST'])
@limiter.limit("7 per minute")
def comment():
    if 'credentials' not in session:
        return redirect(url_for('authorize'))
    
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    video_id = request.form.get('video_id')
    if not video_id:
        return jsonify({'error': 'No video ID provided'}), 400
    
    user_comments = load_user_comments(user_id)
    if not user_comments:
        return jsonify({'error': 'No comments available'}), 400
    
    random_comment = random.choice(user_comments)
    success = YoutubeApi.add_comment(video_id, random_comment)
    
    if success:
        return jsonify({'status': 'success', 'comment': random_comment})
    else:
        return jsonify({'error': 'Cannot add comment on disabled comment sections or livestream videos'}), 500

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # For development only
    app.run(debug=True)