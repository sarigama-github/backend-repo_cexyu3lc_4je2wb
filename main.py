import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, RedirectResponse
from pydantic import BaseModel, EmailStr
from bson import ObjectId
from gridfs import GridFS
from passlib.hash import bcrypt

from database import db
from schemas import Adminuser, Album, Photo, Message, Sharetoken

app = FastAPI(title="flamesblue.com API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Utils

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid ID")


def now_utc():
    return datetime.now(timezone.utc)


def serialize(doc: dict) -> dict:
    if not doc:
        return doc
    d = {**doc}
    if "_id" in d:
        d["id"] = str(d.pop("_id"))
    for k, v in list(d.items()):
        if isinstance(v, datetime):
            d[k] = v.isoformat()
    return d


def fs():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    return GridFS(db)


def album_expiry(album: dict) -> datetime:
    base = album.get("created_at") or now_utc()
    days = int(album.get("expires_in_days", 15))
    return base + timedelta(days=days)


# Auth
class AdminLogin(BaseModel):
    email: EmailStr
    password: str

class ResetRequest(BaseModel):
    email: EmailStr

class ResetConfirm(BaseModel):
    email: EmailStr
    code: str
    password: str

class TokenOut(BaseModel):
    token: str

ADMIN_TOKENS = set()


def require_admin(token: Optional[str] = Query(default=None, alias="token")):
    if token not in ADMIN_TOKENS:
        raise HTTPException(status_code=401, detail="Unauthorized")


@app.post("/api/admin/login", response_model=TokenOut)
def admin_login(payload: AdminLogin):
    u = db["adminuser"].find_one({"email": payload.email})
    if not u:
        # bootstrap default admin if none exist and matches env
        default_email = os.getenv("ADMIN_EMAIL", "admin@flamesblue.com")
        default_pass = os.getenv("ADMIN_PASSWORD", "admin")
        if payload.email == default_email and payload.password == default_pass:
            pwd_hash = bcrypt.hash(default_pass)
            db["adminuser"].insert_one({"email": default_email, "password_hash": pwd_hash, "created_at": now_utc(), "updated_at": now_utc()})
            token = os.urandom(16).hex()
            ADMIN_TOKENS.add(token)
            return TokenOut(token=token)
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not bcrypt.verify(payload.password, u.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = os.urandom(16).hex()
    ADMIN_TOKENS.add(token)
    return TokenOut(token=token)


@app.post("/api/admin/reset/request")
def reset_request(payload: ResetRequest):
    code = os.urandom(3).hex()
    db["adminuser"].update_one({"email": payload.email}, {"$set": {"reset_code": code, "updated_at": now_utc()}})
    # In a production app, email this code. Here we just expose it for testing.
    return {"ok": True, "code": code}


@app.post("/api/admin/reset/confirm")
def reset_confirm(payload: ResetConfirm):
    u = db["adminuser"].find_one({"email": payload.email})
    if not u or u.get("reset_code") != payload.code:
        raise HTTPException(status_code=400, detail="Invalid reset")
    db["adminuser"].update_one({"email": payload.email}, {"$set": {"password_hash": bcrypt.hash(payload.password), "reset_code": None, "updated_at": now_utc()}})
    return {"ok": True}


# Public - Home
@app.get("/api/albums")
def list_albums(q: Optional[str] = None, location: Optional[str] = None, date: Optional[str] = None, limit: int = 60):
    cleanup_expired()
    filt = {}
    if q:
        filt["$or"] = [{"event_name": {"$regex": q, "$options": "i"}}, {"location": {"$regex": q, "$options": "i"}}]
    if location:
        filt["location"] = {"$regex": location, "$options": "i"}
    if date:
        try:
            dt = datetime.fromisoformat(date)
            start = datetime(dt.year, dt.month, dt.day, tzinfo=timezone.utc)
            end = start + timedelta(days=1)
            filt["date"] = {"$gte": start, "$lt": end}
        except Exception:
            pass
    albums = list(db["album"].find(filt).sort("created_at", -1).limit(limit))
    out = []
    for a in albums:
        d = serialize(a)
        exp = album_expiry(a)
        d["expires_at"] = exp.isoformat()
        d["seconds_left"] = max(0, int((exp - now_utc()).total_seconds()))
        out.append(d)
    return {"items": out}


class AlbumCreate(BaseModel):
    event_name: str
    location: Optional[str] = None
    date: datetime
    cover_image_url: Optional[str] = None
    expires_in_days: int = 15


@app.post("/api/albums")
def create_album(payload: AlbumCreate, _: None = Depends(require_admin)):
    doc = Album(**payload.model_dump()).model_dump()
    doc["created_at"], doc["updated_at"] = now_utc(), now_utc()
    album_id = db["album"].insert_one(doc).inserted_id
    return {"id": str(album_id)}


@app.get("/api/albums/{album_id}")
def get_album(album_id: str):
    a = db["album"].find_one({"_id": oid(album_id)})
    if not a:
        raise HTTPException(status_code=404, detail="Album not found")
    d = serialize(a)
    exp = album_expiry(a)
    d["expires_at"] = exp.isoformat()
    d["seconds_left"] = max(0, int((exp - now_utc()).total_seconds()))
    return d


@app.get("/api/albums/{album_id}/photos")
def list_photos(album_id: str):
    cleanup_expired()
    cur = db["photo"].find({"album_id": album_id, "expires_at": {"$gt": now_utc()}}).sort("uploaded_at", -1)
    items = []
    for p in cur:
        d = serialize(p)
        if p.get("expires_at"):
            d["seconds_left"] = max(0, int((p["expires_at"] - now_utc()).total_seconds()))
        items.append(d)
    return {"items": items}


@app.post("/api/albums/{album_id}/photos")
async def upload_photos(album_id: str, files: List[UploadFile] = File(default=None), watermark: bool = Form(default=False), _: None = Depends(require_admin)):
    a = db["album"].find_one({"_id": oid(album_id)})
    if not a:
        raise HTTPException(status_code=404, detail="Album not found")
    fs_ = fs()
    expires_at = album_expiry(a)
    created = 0
    if files:
        for f in files:
            data = await f.read()
            file_id = fs_.put(data, filename=f.filename, content_type=f.content_type)
            doc = Photo(album_id=album_id, file_id=str(file_id), uploaded_at=now_utc(), expires_at=expires_at, watermark=watermark).model_dump()
            db["photo"].insert_one(doc)
            created += 1
    return {"created": created}


@app.get("/api/photos/{photo_id}/image")
def get_photo_image(photo_id: str):
    p = db["photo"].find_one({"_id": oid(photo_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Photo not found")
    if p.get("expires_at") and p["expires_at"] <= now_utc():
        raise HTTPException(status_code=410, detail="Photo expired")
    if p.get("image_url"):
        return RedirectResponse(p["image_url"])  # external URL
    if not p.get("file_id"):
        raise HTTPException(status_code=404, detail="No image")
    g = fs().get(oid(p["file_id"]))
    return StreamingResponse(g, media_type=g.content_type or "image/jpeg")


@app.get("/api/photos/{photo_id}/download")
def download_photo(photo_id: str):
    # free for now; simply stream image
    return get_photo_image(photo_id)


class PhotoEdit(BaseModel):
    brightness: Optional[float] = None
    contrast: Optional[float] = None
    crop: Optional[dict] = None


@app.patch("/api/photos/{photo_id}")
def edit_photo(photo_id: str, payload: PhotoEdit, _: None = Depends(require_admin)):
    updates = {k: v for k, v in payload.model_dump().items() if v is not None}
    if not updates:
        return {"updated": False}
    updates["updated_at"] = now_utc()
    res = db["photo"].update_one({"_id": oid(photo_id)}, {"$set": updates})
    return {"updated": res.modified_count == 1}


@app.delete("/api/photos/{photo_id}")
def delete_photo(photo_id: str, _: None = Depends(require_admin)):
    p = db["photo"].find_one({"_id": oid(photo_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Photo not found")
    try:
        if p.get("file_id"):
            fs().delete(oid(p["file_id"]))
    except Exception:
        pass
    db["photo"].delete_one({"_id": p["_id"]})
    return {"deleted": True}


# Contact
class ContactIn(BaseModel):
    name: str
    email: EmailStr
    event_name: Optional[str] = None
    date: Optional[datetime] = None
    message: str


@app.post("/api/contact")
def submit_contact(payload: ContactIn):
    doc = Message(**payload.model_dump()).model_dump()
    doc["created_at"] = now_utc()
    db["message"].insert_one(doc)
    return {"ok": True}


@app.get("/api/admin/inbox")
def admin_inbox(_: None = Depends(require_admin)):
    msgs = [serialize(m) for m in db["message"].find().sort("created_at", -1)]
    return {"items": msgs}


# Sharing
class ShareIn(BaseModel):
    hours: int = 48


@app.post("/api/photos/{photo_id}/share")
def create_share(photo_id: str, payload: ShareIn):
    p = db["photo"].find_one({"_id": oid(photo_id)})
    if not p:
        raise HTTPException(status_code=404, detail="Photo not found")
    token = os.urandom(8).hex()
    expires_at = now_utc() + timedelta(hours=payload.hours)
    doc = Sharetoken(photo_id=photo_id, token=token, expires_at=expires_at, created_at=now_utc()).model_dump()
    db["sharetoken"].insert_one(doc)
    return {"token": token, "url": f"/share/{token}"}


@app.get("/share/{token}")
def view_share(token: str):
    s = db["sharetoken"].find_one({"token": token})
    if not s:
        raise HTTPException(status_code=404, detail="Invalid link")
    if s["expires_at"] <= now_utc():
        raise HTTPException(status_code=410, detail="Link expired")
    p = db["photo"].find_one({"_id": oid(s["photo_id"])})
    if not p:
        raise HTTPException(status_code=404, detail="Photo not found")
    if p.get("image_url"):
        return RedirectResponse(p["image_url"])  # external URL
    g = fs().get(oid(p["file_id"]))
    return StreamingResponse(g, media_type=g.content_type or "image/jpeg")


# Dashboard
@app.get("/api/admin/metrics")
def metrics(_: None = Depends(require_admin)):
    total_events = db["album"].count_documents({})
    total_photos = db["photo"].count_documents({})
    downloads = db["photo"].aggregate([{ "$group": {"_id": None, "sum": {"$sum": "$downloads"}} }])
    downloads_sum = next(downloads, {"sum": 0}).get("sum", 0)
    recent_albums = [serialize(a) for a in db["album"].find().sort("created_at", -1).limit(5)]
    soon = now_utc() + timedelta(days=3)
    expiring = [serialize(p) for p in db["photo"].find({"expires_at": {"$lte": soon}}).limit(10)]
    return {
        "total_events": total_events,
        "total_photos": total_photos,
        "downloads": downloads_sum,
        "recent_albums": recent_albums,
        "expiring_photos": expiring,
    }


# Expiration + cleanup
@app.post("/api/admin/cleanup")
def run_cleanup(_: None = Depends(require_admin)):
    return cleanup_expired()


def cleanup_expired():
    removed = 0
    now = now_utc()
    cur = db["photo"].find({"expires_at": {"$lte": now}})
    for p in cur:
        try:
            if p.get("file_id"):
                fs().delete(oid(p["file_id"]))
        except Exception:
            pass
        db["photo"].delete_one({"_id": p["_id"]})
        removed += 1
    return {"removed": removed}


@app.get("/")
def root():
    return {"name": "flamesblue.com", "status": "ok"}
