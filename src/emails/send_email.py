import smtplib 
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from datetime import datetime, timezone
from dotenv import load_dotenv

# Load environment variables from .env file
actual_directory = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(os.path.dirname(actual_directory))
load_dotenv(os.path.join(ROOT_DIR, '.env'))

def load_config_file(filename: str) -> dict:
    actual_directory = os.path.dirname(os.path.abspath(__file__))
    config_directory = os.path.join(actual_directory, 'config')
    config_file = os.path.join(config_directory, filename)
    try:
        with open(config_file) as file:
            config = json.loads(file.read())
    except Exception as error:
        print(error)
        config = {}
    return config

def get_time() -> str:
    return datetime.now(tz=timezone.utc).strftime('[%d-%m-%Y || %H:%M:%S]')
            
class Email:
    def __init__(self) -> None:
        self.server: str
        self.server_port: int
        self.from_email: str
        self.to_email: str
        self.password: str
        
    def start(self) -> None:
        config = load_config_file("config.json")
        self.server = os.getenv("EMAIL_SERVER", config.get("gmail_server", "smtp.gmail.com"))
        self.server_port = int(os.getenv("EMAIL_PORT", config.get("gmail_port", 587)))
        self.from_email = os.getenv("EMAIL_FROM", config.get("from"))
        self.to_email = os.getenv("EMAIL_TO", config.get("to"))
        self.password = os.getenv("EMAIL_PASSWORD", config.get("password"))
    
    def send(self, subject: str, message:str) -> None:
        try:
            server = smtplib.SMTP(self.server, self.server_port)
            server.connect(self.server, self.server_port)
            server.starttls()
            server.login(self.from_email, self.password)
            server.sendmail(self.from_email, self.to_email, self.config_messages(subject, message).as_string())
            server.quit()
        except Exception as error:
            pass
            
    def config_messages(self, subject: str, message: str) -> MIMEMultipart:
        msg = MIMEMultipart()
        msg['From'] = self.from_email
        msg['To'] = self.to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(f'{get_time()}: {message}', 'plain'))
        return msg