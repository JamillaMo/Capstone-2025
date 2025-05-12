from sqlalchemy import create_engine, Column, Integer, String, TIMESTAMP
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
from sqlalchemy.sql import func

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
    attack_type = Column(String(100), nullable=False)
    reported_at = Column(TIMESTAMP, server_default=func.current_timestamp())

    def __repr__(self):
        return f"<Report(id={self.id}, ip='{self.ip}', attack_type='{self.attack_type}')>"

# Database connection setup
def setup_database_connection():
    # Replace with correct credentials
    DATABASE_URI = "mysql+mysqlconnector://root:your_password@localhost/my_database"
    engine = create_engine(DATABASE_URI, echo=True)  
    
    # Create all tables if they don't exist
    Base.metadata.create_all(engine)
    
    # Create a configured "Session" class
    Session = sessionmaker(bind=engine)
    
    return Session

# Example usage:
if __name__ == "__main__":
    Session = setup_database_connection()
    session = Session()
    
    # Example query
    users = session.query(User).all()
    print(users)
    
    session.close()