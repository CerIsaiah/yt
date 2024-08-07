from flask import Flask, render_template, request, jsonify, session, redirect, url_for, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.errors import HttpError
import os
import json
import random
from datetime import timedelta
from dotenv import load_dotenv
from google.auth.transport.requests import Request
import requests 

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
CLIENT_SECRETS_FILE = "client_secrets.json"
SCOPES = ["https://www.googleapis.com/auth/youtube.force-ssl", "https://www.googleapis.com/auth/youtube.readonly", "https://www.googleapis.com/auth/youtube"]
API_SERVICE_NAME = "youtube"
API_VERSION = "v3"

class YoutubeApi:
    def __init__(self, credentials):
        self.connection = self.init_connection(credentials)

    def init_connection(self, credentials):
        return build(API_SERVICE_NAME, API_VERSION, credentials=credentials)

    def make_search(self, query, max_results=10):
        try:
            return self.connection.search().list(
                q=query,
                maxResults=max_results,
                part="snippet",
                type="video"
            ).execute()
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
            print(self.connection.commentThreads())
            return True
        except HttpError as e:
            print(f"An error occurred: {e}")
            return False
    #Retunrs a list of comments that match ur specification
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

#################################################################
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
        #load_comments = youtube_api.get_comment_threads(video_id, "disrespectful")
        if success:
            return jsonify({'status': 'success', 'comment': random_comment})
        else:
            return jsonify({'error': 'Unable to post comment. Please check video permissions.'}), 403
    except HttpError as e:
        if e.resp.status == 401:
            # Clear session if unauthorized
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
        #print(results)
        if results is None:
            return jsonify({'error': 'An error occurred while searching'}), 500
        return jsonify(results)
    except HttpError as e:
        if e.resp.status == 401:
            # Clear session if unauthorized
            session.clear()
            return jsonify({'error': 'Authentication failed', 'redirect': url_for('authorize')}), 401
        print(f"Search error: {str(e)}")
        return jsonify({'error': 'An error occurred while searching'}), 500

###########################################################
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
        prompt='select_account'  # This forces Google to show the account selection screen
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
#############################################################
@app.route('/privacy-policy')
def privacy():
    return render_template('privacy-policy.html')

@app.route('/sign_out', methods=['POST'])
def sign_out():
    if 'credentials' in session:
        credentials = Credentials(**session['credentials'])
        if credentials and credentials.valid:
            try:
                # Revoke the token
                requests.post('https://oauth2.googleapis.com/revoke',
                    params={'token': credentials.token},
                    headers = {'content-type': 'application/x-www-form-urlencoded'})
            except:
                pass  # If revoking fails, we'll still clear the session
    
    # Clear the session
    session.clear()
    
    # Prepare a response that clears all cookies
    response = make_response(jsonify({'status': 'success', 'message': 'Signed out successfully'}))
    
    # Clear all cookies set by the application
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
                    # If refresh fails, we'll sign the user out
                    session.clear()
                    return jsonify({'authenticated': False})
            return jsonify({'authenticated': True})
    return jsonify({'authenticated': False})
####################################

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
    app.run(debug=True)