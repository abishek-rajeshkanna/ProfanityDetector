from fastapi import FastAPI, Depends, HTTPException, Header, Security, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
import jwt
import os
import requests

# Database Configuration
DATABASE_URL = "postgresql://postgres:srp12345@srp.cejku0q8c9sd.us-east-1.rds.amazonaws.com/srp_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Password Hashing Context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# User Model
class User(Base):
    __tablename__ = "users"
    email = Column(String, primary_key=True, index=True)
    password = Column(String)
    api_key = Column(String, unique=True)
    name = Column(String)
    mobile = Column(String)

# Pydantic Models for Request Validation
class LoginRequest(BaseModel):
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="securepassword")

class RegisterRequest(BaseModel):
    name: str = Field(..., example="John Doe")
    email: str = Field(..., example="john.doe@example.com")
    password: str = Field(..., example="securepassword")
    mobile: str = Field(..., example="1234567890")

# Create FastAPI App
app = FastAPI()

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Replace "*" with specific origins if needed
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Dependency to Get DB Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Register Route
@app.post("/register")
def register(request: RegisterRequest, db: Session = Depends(get_db)):
    # Check if email is already registered
    existing_user = db.query(User).filter(User.email == request.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Hash password
    hashed_password = pwd_context.hash(request.password)

    # Create new user with API key
    new_user = User(
        name=request.name,
        email=request.email,
        password=hashed_password,
        mobile=request.mobile,
        api_key=os.urandom(16).hex()
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Generate JWT token
    token = jwt.encode({"email": new_user.email}, "SECRET_KEY", algorithm="HS256")

    return {"message": "Registration successful", "token": token}

# Login Route
@app.post("/login")
def login(request: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == request.email).first()
    if not user or not pwd_context.verify(request.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid email or password")

    token = jwt.encode({"email": user.email}, "SECRET_KEY", algorithm="HS256")
    return {"token": token}

# API Key Retrieval Route
security = HTTPBearer()

@app.get("/api-key")
def get_api_key(credentials: HTTPAuthorizationCredentials = Security(security), db: Session = Depends(get_db)):
    try:
        token = credentials.credentials  # Extract the token from the Authorization header
        decoded_token = jwt.decode(token, "SECRET_KEY", algorithms=["HS256"])
        user = db.query(User).filter(User.email == decoded_token["email"]).first()
        if not user:
            raise HTTPException(status_code=400, detail="User not found")
        return {"api_key": user.api_key}
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

def verify_api_key(api_key: str = Header(...), db: Session = Depends(get_db)):
    print(f"Received API key: {api_key}")
    user = db.query(User).filter(User.api_key == api_key).first()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    return user

# Profanity Detection Endpoint
@app.post("/profanity-detect")
async def profanity_detect(
    file: UploadFile = File(...),  # Ensure this is defined correctly
    current_user: User = Depends(verify_api_key)
):
    print(f"Received file: {file.filename}, Content-Type: {file.content_type}")
    """
    This endpoint accepts an image file, forwards it to the external profanity detection API,
    and returns the result to the user.
    """
    try:
        # Forward the image to the external profanity detection API
        response = requests.post(
            "http://44.212.117.2:5000/classify",
            files={"image": (file.filename, file.file, file.content_type)}
        )

        # Check if the external API call was successful
        if response.status_code != 200:
            raise HTTPException(
                status_code=500,
                detail="Error occurred while processing the image with the profanity detection model"
            )

        # Parse the response from the external API
        result = response.json()

        # Return the result to the user
        return {
            "result": result
        }

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"An error occurred while processing the image: {str(e)}"
        )