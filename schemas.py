"""
Fresh Schemas for flamesblue.com

Each Pydantic model maps to a MongoDB collection with the lowercase
class name as the collection name.
"""
from __future__ import annotations
from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Dict, Any
from datetime import datetime

class Adminuser(BaseModel):
    email: EmailStr
    password_hash: str
    reset_code: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Album(BaseModel):
    event_name: str
    location: Optional[str] = None
    date: datetime
    cover_file_id: Optional[str] = None
    cover_image_url: Optional[str] = None
    expires_in_days: int = Field(default=15, ge=1, le=365)
    downloads: int = 0
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

class Photo(BaseModel):
    album_id: str
    file_id: Optional[str] = None
    image_url: Optional[str] = None
    uploaded_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    brightness: float = 1.0
    contrast: float = 1.0
    crop: Optional[Dict[str, float]] = None  # x,y,w,h percentages
    downloads: int = 0
    watermark: bool = False

class Message(BaseModel):
    name: str
    email: EmailStr
    event_name: Optional[str] = None
    date: Optional[datetime] = None
    message: str
    created_at: Optional[datetime] = None

class Sharetoken(BaseModel):
    photo_id: str
    token: str
    expires_at: datetime
    created_at: Optional[datetime] = None
