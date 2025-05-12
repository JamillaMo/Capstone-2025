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
    domain = Column(String(255))
    ip = Column(String(45))
    high = Column(Boolean, default=False)
    critical = Column(Boolean, default=False)
    os = Column(String(100))
    whois = Column(Text)  
    nmap_info = Column(Text, name="Nmap_info") 
    num_vulnerabilities = Column(Integer, name="No. of Vulnerabilities")
    vulnerabilities = Column(Text)
    reported_at = Column(TIMESTAMP, server_default=func.current_timestamp())

    def __repr__(self):
        return f"<Report(id={self.id}, domain='{self.domain}', ip='{self.ip}')>"


class Alert(Base):
    __tablename__ = 'alerts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    alert_info = Column(Text, nullable=False)  # Using Text to allow longer alert messages
    created_at = Column(TIMESTAMP, server_default=func.current_timestamp())

    def __repr__(self):
        return f"<Alert(id={self.id}, alert_info='{self.alert_info[:50]}...')>"
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
