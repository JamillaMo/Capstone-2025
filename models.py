from sqlalchemy import create_engine, Column, Integer, String, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from sqlalchemy.sql import func
from sqlalchemy.exc import SQLAlchemyError

Base = declarative_base()

class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(100), nullable=False, unique=True)
    email = Column(String(100), nullable=False, unique=True)
    password = Column(String(255), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())

    def __repr__(self):
        return f"<User(id={self.id}, username='{self.username}', email='{self.email}')>"

class Report(Base):
    __tablename__ = 'reports'  

    id = Column(Integer, primary_key=True, autoincrement=True)
    ip = Column(String(45), nullable=False)
    description = Column(String(100), nullable=False)
    reported_at = Column(TIMESTAMP, server_default=func.current_timestamp())

    def __repr__(self):
        return f"<Report(id={self.id}, ip='{self.ip}', attack_type='{self.attack_type}')>"

# Environment variables
SECRET_KEY = "your_secret_key_here"
DATABASE_URL = "sqlite:///sentriscan.db"  # Replace with actual database URL
MAIL_SERVER = "smtp.example.com"        # Replace with mail server
MAIL_PORT = 587                         # Replace with mail server port
MAIL_USE_TLS = True                     # Use 'true' or 'false'
MAIL_USERNAME = "your_email@example.com"
MAIL_PASSWORD = "your_email_password"
MAIL_DEFAULT_SENDER = "your_email@example.com"

# Database connection setup
def setup_database_connection():
    engine = create_engine(DATABASE_URL, echo=True)  
    
    # Create all tables if they don't exist
    Base.metadata.create_all(engine)
    
    # Create a configured "Session" class
    Session = sessionmaker(bind=engine)
    
    return Session

def save_scan_to_reports(scan_summary):
    """
    Save scan summary data to the reports table.
    """
    Session = setup_database_connection()  # Get the session factory
    session = Session()

    try:
        for row in scan_summary:
            report = Report(
                ip=row.get("ip", "N/A"),
                description=row.get("Feedback", "N/A"),  # Use "Feedback" as the description
                reported_at=datetime.utcnow()
            )
            session.add(report)
        session.commit()
        print("Scan summary successfully saved to the reports table.")
    except SQLAlchemyError as e:
        session.rollback()
        print(f"Error saving scan summary to the reports table: {e}")
    finally:
        session.close()

# Example usage:
if __name__ == "__main__":
    Session = setup_database_connection()
    session = Session()
    
    # Example query
    users = session.query(User).all()
    print(users)
    
    session.close()