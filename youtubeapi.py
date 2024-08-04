from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import os
import json


class YoutubeApi:
    scopes = ["https://www.googleapis.com/auth/youtube.force-ssl"]
    secret_path = "secret.json"
    token_path = "token.json"
    api_service = "youtube"
    api_version = "v3"

    def __init__(self, max_results, region):
        self.max_results = max_results
        self.region = region
        self.connection = self.init_connection()

    def init_connection(self):
        credentials = None
        # Check if token file exists
        if os.path.exists(self.token_path):
            credentials = Credentials.from_authorized_user_file(self.token_path, self.scopes)

        # If there are no valid credentials available, let the user log in.
        if not credentials or not credentials.valid:
            if credentials and credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
            else:
                flow = InstalledAppFlow.from_client_secrets_file(self.secret_path, self.scopes)
                credentials = flow.run_local_server()

            # Save the credentials for the next run
            with open(self.token_path, 'w') as token:
                token.write(credentials.to_json())

        return build(self.api_service, self.api_version, credentials=credentials)

    @staticmethod
    def is_forbidden_action_error(error):
        parsed_error = json.loads(error.content)
        return error.resp.status == 403 or parsed_error['error']['message'] == "This action is not available for the item."

    def make_search(self, next_page_token, query):
        return self.connection.search().list(
            q=query,
            maxResults=self.max_results,
            part="snippet",
            type="video",
            pageToken=next_page_token,
            regionCode=self.region
        ).execute()

    def is_video_liked_or_unliked(self, video_id):
        return self.connection.videos().getRating(
            id=video_id
        ).execute()

    def add_comment(self, video_id, comment):
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

    def add_rating(self, video_id, rating):
        self.connection.videos().rate(
            id=video_id,
            rating=rating
        ).execute()
