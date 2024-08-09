from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_sqlalchemy import SQLAlchemy
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError
import os
import json
import random
from datetime import timedelta, datetime
from dotenv import load_dotenv
from google.auth.transport.requests import Request
import requests 
from youtube_transcript_api import YouTubeTranscriptApi
from openai import OpenAI
from flask_migrate import Migrate



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

CLIENT_CONFIG = {
    "web": {
        "client_id": os.getenv('GOOGLE_CLIENT_ID'),
        "project_id": os.getenv('GOOGLE_PROJECT_ID'),
        "auth_uri": "https://accounts.google.com/o/oauth2/auth",
        "token_uri": "https://oauth2.googleapis.com/token",
        "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
        "client_secret": os.getenv('GOOGLE_CLIENT_SECRET'),
        "redirect_uris": ["http://localhost:8000/","http://localhost:0/","http://localhost:5000/oauth2callback","http://127.0.0.1:5000/search","http://127.0.0.1:5000/","http://127.0.0.1:5000/oauth2callback"]
    }
}

# OAuth 2.0 configuration
SCOPES = ["https://www.googleapis.com/auth/youtube.force-ssl", "https://www.googleapis.com/auth/youtube.readonly", "https://www.googleapis.com/auth/youtube"]
API_SERVICE_NAME = "youtube"
API_VERSION = "v3"

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] =  os.getenv("DB_STRING")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db)



# Define UserInteraction model
class UserInteraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(50), nullable=False)
    video_id = db.Column(db.String(50), nullable=False)
    interaction_type = db.Column(db.String(20), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# Define VideoTranscript model
class VideoTranscript(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    video_id = db.Column(db.String(50), unique=True, nullable=False)
    transcript = db.Column(db.Text, nullable=False)
    summary = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# OpenAI client
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class YoutubeApi:
    def __init__(self, credentials):
        self.connection = self.init_connection(credentials)

    def init_connection(self, credentials):
        return build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    def make_search(self, query, max_results=20):
        try:
            results = self.connection.search().list(
                q=query,
                maxResults=max_results,
                part="snippet",
                type="video"
            ).execute()

            # Filter out videos the user has interacted with
            user_id = session.get('user_id')
            interacted_videos = UserInteraction.query.filter_by(user_id=user_id).with_entities(UserInteraction.video_id).all()
            interacted_video_ids = [video.video_id for video in interacted_videos]

            filtered_results = [
                video for video in results.get('items', [])
                if video['id']['videoId'] not in interacted_video_ids
            ]

            results['items'] = filtered_results
            return results
        except HttpError as e:
            print(f"An error occurred: {e}")
            return None

    def add_comment(self, video_id, comment):
        try:
            self.connection.commentThreads().insert(
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
            
            # Record the interaction
            user_id = session.get('user_id')
            interaction = UserInteraction(user_id=user_id, video_id=video_id, interaction_type='comment')
            db.session.add(interaction)
            db.session.commit()

            return True
        except HttpError as e:
            print(f"An error occurred: {e}")
            return False

    def get_comment_threads(self, video_id, search):
        results = self.connection.commentThreads().list(
            part="snippet",
            videoId=video_id,
            textFormat="plainText",
            searchTerms=search,
            maxResults=10,
        ).execute()

        for item in results["items"]:
            comment = item["snippet"]["topLevelComment"]
            author = comment["snippet"]["authorDisplayName"]
            text = comment["snippet"]["textDisplay"]
            print(author, text)

        return results["items"]

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

@app.route('/')
def index():
    return render_template('index.html')

def get_youtube_api():
    if 'credentials' not in session:
        return None
    credentials = Credentials(**session['credentials'])
    if not credentials or not credentials.valid:
        return None
    return YoutubeApi(credentials)

def credentials_to_dict(credentials):
    return {
        'token': credentials.token,
        'refresh_token': credentials.refresh_token,
        'token_uri': credentials.token_uri,
        'client_id': credentials.client_id,
        'client_secret': credentials.client_secret,
        'scopes': credentials.scopes
    }

@app.route('/comment', methods=['POST'])
@limiter.limit("7 per minute")
def comment():
    youtube_api = get_youtube_api()
    if not youtube_api:
        return jsonify({'error': 'Not authenticated. Please authorize first.'}), 401

    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401

    video_id = request.form.get('video_id')
    if not video_id:
        return jsonify({'error': 'No video ID provided'}), 400
    
    user_comments = load_user_comments(user_id)
    if not user_comments:
        return jsonify({'error': 'You have no comments to send'}), 400
    
    random_comment = random.choice(user_comments)
    try:
        success = youtube_api.add_comment(video_id, random_comment)
        if success:
            return jsonify({'status': 'success', 'comment': random_comment})
        else:
            return jsonify({'error': 'Unable to post comment. Please check video permissions.'}), 403
    except HttpError as e:
        if e.resp.status == 401:
            session.clear()
            return jsonify({'error': 'Authentication failed', 'redirect': url_for('authorize')}), 401
        error_message = e.error_details[0]['message'] if e.error_details else str(e)
        return jsonify({'error': f'YouTube API error: {error_message}'}), e.resp.status

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
    youtube_api = get_youtube_api()
    if not youtube_api:
        return jsonify({'error': 'Not authenticated', 'redirect': url_for('authorize')}), 401

    query = request.form.get('query')
    if not query:
        return jsonify({'error': 'No query provided'}), 400
    
    try:
        results = youtube_api.make_search(query)
        if results is None:
            return jsonify({'error': 'An error occurred while searching'}), 500
        return jsonify(results)
    except HttpError as e:
        if e.resp.status == 401:
            session.clear()
            return jsonify({'error': 'Authentication failed', 'redirect': url_for('authorize')}), 401
        print(f"Search error: {str(e)}")
        return jsonify({'error': 'An error occurred while searching'}), 500

@app.route('/authorize')
def authorize():
    flow = Flow.from_client_config(
        CLIENT_CONFIG,
        scopes=SCOPES,
        redirect_uri=url_for('oauth2callback', _external=True)
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='select_account'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    try:
        flow = Flow.from_client_config(
            CLIENT_CONFIG,
            scopes=SCOPES,
            state=session['state']
        )
        flow.redirect_uri = url_for('oauth2callback', _external=True)

        authorization_response = request.url
        flow.fetch_token(authorization_response=authorization_response)

        credentials = flow.credentials
        session['credentials'] = credentials_to_dict(credentials)
        return redirect(url_for('index'))
    except Exception as e:
        print(f"OAuth callback error: {str(e)}")
        return redirect(url_for('reauth'))

@app.before_request
def before_request():
    session.permanent = True
    if 'user_id' not in session:
        session['user_id'] = str(random.randint(1000000, 9999999))

@app.route('/clear')
def clear_credentials():
    if 'credentials' in session:
        del session['credentials']
    return redirect(url_for('index'))

@app.route('/reauth')
def reauth():
    session.clear()
    return redirect(url_for('authorize'))

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({'error': 'Rate limit exceeded'}), 429

@app.route('/privacy-policy')
def privacy():
    return render_template('privacy-policy.html')

@app.route('/sign_out', methods=['POST'])
def sign_out():
    if 'credentials' in session:
        credentials = Credentials(**session['credentials'])
        if credentials and credentials.valid:
            try:
                requests.post('https://oauth2.googleapis.com/revoke',
                    params={'token': credentials.token},
                    headers = {'content-type': 'application/x-www-form-urlencoded'})
            except:
                pass
    
    session.clear()
    
    response = make_response(jsonify({'status': 'success', 'message': 'Signed out successfully'}))
    
    for cookie in request.cookies:
        response.delete_cookie(cookie)
    
    return response

@app.route('/auth_status')
def auth_status():
    if 'credentials' in session:
        credentials = Credentials(**session['credentials'])
        if credentials and credentials.valid:
            if credentials.expired and credentials.refresh_token:
                try:
                    credentials.refresh(Request())
                    session['credentials'] = credentials_to_dict(credentials)
                    return jsonify({'authenticated': True})
                except:
                    session.clear()
                    return jsonify({'authenticated': False})
            return jsonify({'authenticated': True})
    return jsonify({'authenticated': False})

@app.route('/get_interaction_history')
def get_interaction_history():
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'User not authenticated'}), 401
    
    interactions = UserInteraction.query.filter_by(user_id=user_id).order_by(UserInteraction.timestamp.desc()).all()
    
    interaction_list = []
    for interaction in interactions:
        video_info = get_video_info(interaction.video_id)
        interaction_list.append({
            'video_id': interaction.video_id,
            'video_title': video_info.get('title', 'Unknown Title'),
            'interaction_type': interaction.interaction_type,
            'timestamp': interaction.timestamp.isoformat()
        })
    
    return jsonify({'interactions': interaction_list})

def get_video_info(video_id):
    youtube_api = get_youtube_api()
    if not youtube_api:
        return {'title': 'Unknown Title'}
    
    try:
        response = youtube_api.connection.videos().list(
            part='snippet',
            id=video_id
        ).execute()
        
        if response['items']:
            return {'title': response['items'][0]['snippet']['title']}
        else:
            return {'title': 'Unknown Title'}
    except Exception as e:
        print(f"Error fetching video info: {e}")
        return {'title': 'Unknown Title'}

@app.route('/interaction_history')
def interaction_history():
    return render_template('interaction_history.html')


@app.route('/get_bulk_transcripts', methods=['POST'])
@limiter.limit("2 per minute")
def get_bulk_transcripts():
    video_ids = request.json.get('video_ids')
    if not video_ids or not isinstance(video_ids, list):
        return jsonify({'error': 'Invalid or missing video IDs'}), 400

    results = {}
    for video_id in video_ids:
        existing_transcript = VideoTranscript.query.filter_by(video_id=video_id).first()
        if existing_transcript:
            results[video_id] = {
                'summary': existing_transcript.summary
            }
        else:
            try:
                srt = YouTubeTranscriptApi.get_transcript(video_id)
                text_list = [i['text'] for i in srt]
                full_transcript = ' '.join(text_list)

                try:
                    completion = client.chat.completions.create(
                        model="gpt-4",
                        messages=[
                            {"role": "system", "content": "You are a helpful assistant. Create a bullet point summary of the following transcript:"},
                            {"role": "user", "content": f"Create a 2 sentence summary of:\n\n{full_transcript[:4000]}"}
                        ]
                    )
                    summary = completion.choices[0].message.content
                except Exception as e:
                    print(f"Error generating summary for video {video_id}: {str(e)}")
                    summary = "Summary generation failed. Please try again later."

                new_transcript = VideoTranscript(video_id=video_id, transcript=full_transcript, summary=summary)
                db.session.add(new_transcript)
                db.session.commit()

                results[video_id] = {
                    'summary': summary
                }
            except Exception as e:
                print(f"Error processing transcript for video {video_id}: {str(e)}")
                results[video_id] = {
                    'summary': "No captions available"
                }

    return jsonify(results)


def apply_migrations():
    from flask_migrate import upgrade
    with app.app_context():
        upgrade()

if __name__ == '__main__':
    apply_migrations()
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(debug=True)

  
   
"""with app.app_context():
        db.create_all()    """