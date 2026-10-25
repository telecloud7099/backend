import os
import uuid
import hashlib
import logging
from datetime import datetime
from typing import Optional
from uuid import UUID, uuid4

from sqlmodel import Field, Session, SQLModel, create_engine, select
from sqlalchemy import BigInteger, Column, UniqueConstraint, Index, text
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

_raw_url = os.getenv("DATABASE_URL", "")
if not _raw_url:
    raise ValueError("DATABASE_URL environment variable is required")
# Neon and some providers emit postgres:// — SQLAlchemy requires postgresql://
DATABASE_URL = _raw_url.replace("postgres://", "postgresql://", 1) if _raw_url.startswith("postgres://") else _raw_url

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,   # Detect stale connections before use (fixes post-restart 500 errors)
    pool_recycle=300,     # Recycle connections after 5 minutes
)

ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY") or os.getenv("SECRET_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY (or SECRET_KEY) environment variable is required")
_cipher = Fernet(ENCRYPTION_KEY.encode())


def encrypt(value: str) -> str:
    return _cipher.encrypt(value.encode()).decode()


def decrypt(value: str) -> str:
    return _cipher.decrypt(value.encode()).decode()


def phone_to_hash(phone: str) -> str:
    return hashlib.sha256(phone.encode()).hexdigest()


# ── Models ────────────────────────────────────────────────────────────────────

class User(SQLModel, table=True):
    __tablename__ = "users"
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    telegram_user_id: int = Field(sa_column=Column("telegram_user_id", BigInteger(), unique=True, nullable=False, index=True))
    username: Optional[str] = Field(default=None)
    first_name: Optional[str] = Field(default=None)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class UserApiCredentials(SQLModel, table=True):
    __tablename__ = "user_api_credentials"
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    telegram_user_id: int = Field(sa_column=Column("telegram_user_id", BigInteger(), unique=True, nullable=False, index=True))
    phone_hash: str = Field(index=True)
    api_id_encrypted: str
    api_hash_encrypted: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class UserTelegramSession(SQLModel, table=True):
    __tablename__ = "user_sessions"
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    telegram_user_id: int = Field(sa_column=Column("telegram_user_id", BigInteger(), unique=True, nullable=False, index=True))
    string_session_encrypted: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Folder(SQLModel, table=True):
    __tablename__ = "folders"
    __table_args__ = (UniqueConstraint("telegram_user_id", "name", name="uq_folders_user_name"),)
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    telegram_user_id: int = Field(sa_column=Column("telegram_user_id", BigInteger(), nullable=False, index=True))
    name: str
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class TelegramFile(SQLModel, table=True):
    __tablename__ = "files"
    __table_args__ = (
        UniqueConstraint("telegram_user_id", "telegram_message_id", name="uq_files_user_msg"),
        Index("ix_files_user_uploaded", "telegram_user_id", "uploaded_at"),
        Index("ix_files_folder_id", "folder_id"),
    )
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    telegram_user_id: int = Field(sa_column=Column("telegram_user_id", BigInteger(), nullable=False, index=True))
    folder_id: Optional[UUID] = Field(default=None, foreign_key="folders.id")
    # Null for chunked files — a chunked file has no single message; see FileChunk.
    telegram_message_id: Optional[int] = Field(default=None, sa_column=Column("telegram_message_id", BigInteger(), nullable=True, index=True))
    filename: str
    mime_type: str = Field(default="application/octet-stream")
    file_size: int = Field(sa_column=Column("file_size", BigInteger(), nullable=False, server_default="0"))
    category: str = Field(default="Other")
    uploaded_at: Optional[datetime] = Field(default=None)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    is_chunked: bool = Field(default=False, sa_column=Column("is_chunked", nullable=False, server_default="false"))
    chunk_count: int = Field(default=1, sa_column=Column("chunk_count", nullable=False, server_default="1"))
    # sha256 of the concatenation of each chunk's sha256 — cheap whole-file integrity check, avoids rehashing gigabytes
    content_signature: Optional[str] = Field(default=None)


class FileChunk(SQLModel, table=True):
    __tablename__ = "file_chunks"
    __table_args__ = (
        # Uniqueness is anchored on the session while the upload is in progress (file_id is
        # still null at that point). One session maps to exactly one file, so this also
        # guarantees (file_id, part_number) uniqueness once file_id is populated on completion.
        UniqueConstraint("session_id", "part_number", name="uq_chunks_session_part"),
        Index("ix_chunks_file_id", "file_id"),
    )
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    session_id: UUID = Field(foreign_key="upload_sessions.id", nullable=False)
    # Null until the owning UploadSession completes and a TelegramFile row is created.
    file_id: Optional[UUID] = Field(default=None, foreign_key="files.id")
    part_number: int
    telegram_message_id: int = Field(sa_column=Column("telegram_message_id", BigInteger(), nullable=False))
    size: int = Field(sa_column=Column("size", BigInteger(), nullable=False))
    sha256: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class UploadSession(SQLModel, table=True):
    __tablename__ = "upload_sessions"
    __table_args__ = (
        Index("ix_upload_sessions_user_status", "telegram_user_id", "status"),
    )
    id: UUID = Field(default_factory=uuid4, primary_key=True)
    telegram_user_id: int = Field(sa_column=Column("telegram_user_id", BigInteger(), nullable=False, index=True))
    filename: str
    total_size: int = Field(sa_column=Column("total_size", BigInteger(), nullable=False))
    mime_type: str = Field(default="application/octet-stream")
    folder_id: Optional[UUID] = Field(default=None, foreign_key="folders.id")
    chunk_size: int = Field(sa_column=Column("chunk_size", BigInteger(), nullable=False))
    total_chunks: int
    next_part_number: int = Field(default=1)
    bytes_uploaded: int = Field(default=0, sa_column=Column("bytes_uploaded", BigInteger(), nullable=False, server_default="0"))
    status: str = Field(default="uploading")  # uploading | completed | failed | aborted
    file_id: Optional[UUID] = Field(default=None, foreign_key="files.id")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class SyncState(SQLModel, table=True):
    __tablename__ = "sync_state"
    telegram_user_id: int = Field(sa_column=Column("telegram_user_id", BigInteger(), primary_key=True))
    last_sync_at: Optional[datetime] = Field(default=None)
    newest_msg_id: int = Field(default=0, sa_column=Column("newest_msg_id", BigInteger(), nullable=False, server_default="0"))


class UserSettings(SQLModel, table=True):
    __tablename__ = "user_settings"
    telegram_user_id: int = Field(sa_column=Column("telegram_user_id", BigInteger(), primary_key=True))
    theme: str = Field(default="dark")
    default_upload_folder: Optional[str] = Field(default=None)
    max_scan_messages: int = Field(default=2000)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


# ── Init ──────────────────────────────────────────────────────────────────────

def _apply_migrations() -> None:
    """Idempotently add columns/indexes to existing databases. create_all only covers new tables."""
    stmts = [
        "CREATE INDEX IF NOT EXISTS ix_files_user_uploaded ON files (telegram_user_id, uploaded_at DESC)",
        "CREATE INDEX IF NOT EXISTS ix_files_folder_id ON files (folder_id)",
        "ALTER TABLE files ADD COLUMN IF NOT EXISTS is_chunked boolean NOT NULL DEFAULT false",
        "ALTER TABLE files ADD COLUMN IF NOT EXISTS chunk_count integer NOT NULL DEFAULT 1",
        "ALTER TABLE files ADD COLUMN IF NOT EXISTS content_signature varchar",
        "ALTER TABLE files ALTER COLUMN telegram_message_id DROP NOT NULL",
    ]
    with engine.connect() as conn:
        for stmt in stmts:
            conn.execute(text(stmt))
        conn.commit()
    logger.info("Database migrations applied")


def init_db():
    SQLModel.metadata.create_all(engine)
    _apply_migrations()


def get_session():
    with Session(engine) as session:
        yield session


# ── User helpers ──────────────────────────────────────────────────────────────

def get_or_create_user(telegram_user_id: int, username: Optional[str], first_name: Optional[str]) -> User:
    with Session(engine) as s:
        row = s.exec(select(User).where(User.telegram_user_id == telegram_user_id)).first()
        if row:
            row.username = username
            row.first_name = first_name
            row.updated_at = datetime.utcnow()
            s.add(row)
            s.commit()
            s.refresh(row)
            return row
        user = User(telegram_user_id=telegram_user_id, username=username, first_name=first_name)
        s.add(user)
        s.commit()
        s.refresh(user)
        return user


def get_user(telegram_user_id: int) -> Optional[User]:
    with Session(engine) as s:
        return s.exec(select(User).where(User.telegram_user_id == telegram_user_id)).first()


# ── In-memory credential caches (avoids repeated DB round-trips per Telegram call) ──
_cred_cache: dict[int, tuple[int, str]] = {}   # user_id → (api_id, api_hash)
_session_cache: dict[int, str | None] = {}     # user_id → string_session (None = no session)


# ── API credentials helpers ───────────────────────────────────────────────────

def save_api_credentials(telegram_user_id: int, phone: str, api_id: int, api_hash: str):
    ph = phone_to_hash(phone)
    with Session(engine) as s:
        row = s.exec(select(UserApiCredentials).where(UserApiCredentials.telegram_user_id == telegram_user_id)).first()
        if row:
            row.phone_hash = ph
            row.api_id_encrypted = encrypt(str(api_id))
            row.api_hash_encrypted = encrypt(api_hash)
            row.updated_at = datetime.utcnow()
            s.add(row)
        else:
            s.add(UserApiCredentials(
                telegram_user_id=telegram_user_id,
                phone_hash=ph,
                api_id_encrypted=encrypt(str(api_id)),
                api_hash_encrypted=encrypt(api_hash),
            ))
        s.commit()
    _cred_cache[telegram_user_id] = (api_id, api_hash)


def get_api_credentials(telegram_user_id: int) -> tuple[Optional[int], Optional[str]]:
    if telegram_user_id in _cred_cache:
        return _cred_cache[telegram_user_id]
    with Session(engine) as s:
        row = s.exec(select(UserApiCredentials).where(UserApiCredentials.telegram_user_id == telegram_user_id)).first()
        if not row:
            return None, None
        try:
            result = int(decrypt(row.api_id_encrypted)), decrypt(row.api_hash_encrypted)
            _cred_cache[telegram_user_id] = result
            return result
        except Exception:
            return None, None


def credentials_exist_for_phone(phone: str) -> bool:
    ph = phone_to_hash(phone)
    with Session(engine) as s:
        row = s.exec(select(UserApiCredentials).where(UserApiCredentials.phone_hash == ph)).first()
        return row is not None


def get_api_credentials_by_phone(phone: str) -> tuple[Optional[int], Optional[str]]:
    ph = phone_to_hash(phone)
    with Session(engine) as s:
        row = s.exec(select(UserApiCredentials).where(UserApiCredentials.phone_hash == ph)).first()
        if not row:
            return None, None
        try:
            return int(decrypt(row.api_id_encrypted)), decrypt(row.api_hash_encrypted)
        except Exception:
            return None, None


# ── StringSession helpers ────────────────────────────────────────────────────

def save_string_session(telegram_user_id: int, string_session: str):
    _session_cache[telegram_user_id] = string_session
    with Session(engine) as s:
        row = s.exec(select(UserTelegramSession).where(UserTelegramSession.telegram_user_id == telegram_user_id)).first()
        if row:
            row.string_session_encrypted = encrypt(string_session)
            row.updated_at = datetime.utcnow()
            s.add(row)
        else:
            s.add(UserTelegramSession(
                telegram_user_id=telegram_user_id,
                string_session_encrypted=encrypt(string_session),
            ))
        s.commit()


def load_string_session(telegram_user_id: int) -> Optional[str]:
    if telegram_user_id in _session_cache:
        return _session_cache[telegram_user_id]
    with Session(engine) as s:
        row = s.exec(select(UserTelegramSession).where(UserTelegramSession.telegram_user_id == telegram_user_id)).first()
        if not row:
            _session_cache[telegram_user_id] = None
            return None
        try:
            result = decrypt(row.string_session_encrypted)
            _session_cache[telegram_user_id] = result
            return result
        except Exception:
            return None


# ── Folder helpers ────────────────────────────────────────────────────────────

def get_folders(telegram_user_id: int) -> list[dict]:
    with Session(engine) as s:
        rows = s.exec(select(Folder).where(Folder.telegram_user_id == telegram_user_id).order_by(Folder.name)).all()
        return [{"id": str(r.id), "name": r.name} for r in rows]


def get_folder_by_name(telegram_user_id: int, name: str) -> Optional[Folder]:
    with Session(engine) as s:
        return s.exec(select(Folder).where(
            Folder.telegram_user_id == telegram_user_id,
            Folder.name == name,
        )).first()


def get_folder_by_id(folder_id: UUID) -> Optional[Folder]:
    with Session(engine) as s:
        return s.get(Folder, folder_id)


def folder_exists(telegram_user_id: int, name: str) -> bool:
    return get_folder_by_name(telegram_user_id, name) is not None


def add_folder(telegram_user_id: int, name: str) -> Folder:
    existing = get_folder_by_name(telegram_user_id, name)
    if existing:
        return existing
    with Session(engine) as s:
        folder = Folder(telegram_user_id=telegram_user_id, name=name)
        s.add(folder)
        s.commit()
        s.refresh(folder)
        return folder


def rename_folder_db(telegram_user_id: int, old_name: str, new_name: str):
    with Session(engine) as s:
        row = s.exec(select(Folder).where(
            Folder.telegram_user_id == telegram_user_id,
            Folder.name == old_name,
        )).first()
        if row:
            row.name = new_name
            row.updated_at = datetime.utcnow()
            s.add(row)
            s.commit()


def delete_folder_db(telegram_user_id: int, name: str):
    with Session(engine) as s:
        row = s.exec(select(Folder).where(
            Folder.telegram_user_id == telegram_user_id,
            Folder.name == name,
        )).first()
        if row:
            # Unassign files in this folder
            files = s.exec(select(TelegramFile).where(TelegramFile.folder_id == row.id)).all()
            for f in files:
                f.folder_id = None
                s.add(f)
            s.delete(row)
            s.commit()


def delete_all_folders(telegram_user_id: int):
    with Session(engine) as s:
        rows = s.exec(select(Folder).where(Folder.telegram_user_id == telegram_user_id)).all()
        for row in rows:
            s.delete(row)
        s.commit()


# ── File helpers ──────────────────────────────────────────────────────────────

def _file_to_dict(f: TelegramFile, folder_name: Optional[str] = None) -> dict:
    return {
        "id": str(f.id),
        "name": f.filename,
        "size": f.file_size,
        "mime_type": f.mime_type,
        "date": f.uploaded_at.isoformat() if f.uploaded_at else None,
        "category": f.category,
        "folder_id": str(f.folder_id) if f.folder_id else None,
        "folder_name": folder_name,
    }


def get_file_by_id(telegram_user_id: int, file_id: UUID) -> Optional[TelegramFile]:
    with Session(engine) as s:
        return s.exec(select(TelegramFile).where(
            TelegramFile.telegram_user_id == telegram_user_id,
            TelegramFile.id == file_id,
        )).first()


def db_get_files(telegram_user_id: int) -> list[dict]:
    with Session(engine) as s:
        # Single LEFT JOIN eliminates a full Neon round-trip vs two separate queries
        stmt = (
            select(TelegramFile, Folder.name.label("folder_name"))
            .outerjoin(Folder, TelegramFile.folder_id == Folder.id)
            .where(TelegramFile.telegram_user_id == telegram_user_id)
            .order_by(TelegramFile.uploaded_at.desc())
        )
        rows = s.exec(stmt).all()
        return [_file_to_dict(f, folder_name) for f, folder_name in rows]


def db_upsert_files(telegram_user_id: int, files: list[dict]):
    with Session(engine) as s:
        for f in files:
            existing = s.exec(select(TelegramFile).where(
                TelegramFile.telegram_user_id == telegram_user_id,
                TelegramFile.telegram_message_id == f["id"],
            )).first()

            folder_id: Optional[UUID] = None
            caption = f.get("caption", "").strip()
            if caption:
                folder = s.exec(select(Folder).where(
                    Folder.telegram_user_id == telegram_user_id,
                    Folder.name == caption,
                )).first()
                if folder:
                    folder_id = folder.id
                else:
                    new_folder = Folder(telegram_user_id=telegram_user_id, name=caption)
                    s.add(new_folder)
                    s.flush()
                    folder_id = new_folder.id

            uploaded_at = None
            if f.get("date"):
                try:
                    uploaded_at = datetime.fromisoformat(f["date"].replace("Z", "+00:00"))
                except Exception:
                    pass

            if existing:
                existing.filename = f["name"]
                existing.file_size = f.get("size", 0)
                existing.mime_type = f.get("mime_type", "application/octet-stream")
                existing.category = f.get("category", "Other")
                existing.uploaded_at = uploaded_at
                existing.updated_at = datetime.utcnow()
                if folder_id is not None:
                    existing.folder_id = folder_id
                s.add(existing)
            else:
                s.add(TelegramFile(
                    telegram_user_id=telegram_user_id,
                    telegram_message_id=f["id"],
                    folder_id=folder_id,
                    filename=f["name"],
                    mime_type=f.get("mime_type", "application/octet-stream"),
                    file_size=f.get("size", 0),
                    category=f.get("category", "Other"),
                    uploaded_at=uploaded_at,
                ))
        s.commit()


def db_insert_file(telegram_user_id: int, msg_id: int, filename: str,
                   mime_type: str, file_size: int, category: str,
                   uploaded_at: Optional[datetime], folder_id: Optional[UUID]):
    with Session(engine) as s:
        existing = s.exec(select(TelegramFile).where(
            TelegramFile.telegram_user_id == telegram_user_id,
            TelegramFile.telegram_message_id == msg_id,
        )).first()
        if existing:
            return
        s.add(TelegramFile(
            telegram_user_id=telegram_user_id,
            telegram_message_id=msg_id,
            folder_id=folder_id,
            filename=filename,
            mime_type=mime_type,
            file_size=file_size,
            category=category,
            uploaded_at=uploaded_at,
        ))
        s.commit()


def db_delete_files_by_ids(telegram_user_id: int, file_ids: list[UUID]) -> list[int]:
    """Deletes the given logical files (and any chunk rows). Returns the Telegram message ids
    the caller must delete from Telegram — one per plain file, all parts for a chunked file."""
    with Session(engine) as s:
        rows = s.exec(select(TelegramFile).where(
            TelegramFile.telegram_user_id == telegram_user_id,
            TelegramFile.id.in_(file_ids),
        )).all()
        message_ids: list[int] = []
        for row in rows:
            if row.is_chunked:
                chunks = s.exec(select(FileChunk).where(FileChunk.file_id == row.id)).all()
                message_ids.extend(c.telegram_message_id for c in chunks)
                session_ids = {c.session_id for c in chunks}
                for c in chunks:
                    s.delete(c)
                # The completed UploadSession still references this file (file_id FK) —
                # it must go before the file row or the delete violates that constraint.
                # SQLAlchemy doesn't infer cross-table delete ordering from a plain FK
                # column (no relationship() is declared here), so flush explicitly.
                for sid in session_ids:
                    session = s.get(UploadSession, sid)
                    if session:
                        s.delete(session)
                s.flush()
            elif row.telegram_message_id is not None:
                message_ids.append(row.telegram_message_id)
            s.delete(row)
        s.commit()
        return message_ids


def db_move_files(telegram_user_id: int, file_ids: list[UUID], folder_id: Optional[UUID]):
    with Session(engine) as s:
        rows = s.exec(select(TelegramFile).where(
            TelegramFile.telegram_user_id == telegram_user_id,
            TelegramFile.id.in_(file_ids),
        )).all()
        for row in rows:
            row.folder_id = folder_id
            row.updated_at = datetime.utcnow()
            s.add(row)
        s.commit()


def db_get_files_in_folder(telegram_user_id: int, folder_id: UUID) -> list[dict]:
    with Session(engine) as s:
        folder = s.get(Folder, folder_id)
        folder_name = folder.name if folder else None
        rows = s.exec(select(TelegramFile).where(
            TelegramFile.telegram_user_id == telegram_user_id,
            TelegramFile.folder_id == folder_id,
        ).order_by(TelegramFile.uploaded_at.desc())).all()
        return [_file_to_dict(r, folder_name) for r in rows]


def db_get_folder_counts(telegram_user_id: int) -> dict:
    with Session(engine) as s:
        folders = s.exec(select(Folder).where(Folder.telegram_user_id == telegram_user_id)).all()
        all_files = s.exec(select(TelegramFile).where(TelegramFile.telegram_user_id == telegram_user_id)).all()
        total_files = len(all_files)
        total_size = sum(f.file_size for f in all_files)
        # Build lookup in Python — avoids N individual DB queries
        folder_id_to_name: dict[UUID, str] = {f.id: f.name for f in folders}
        counts: dict[str, int] = {f.name: 0 for f in folders}
        for file in all_files:
            if file.folder_id and file.folder_id in folder_id_to_name:
                counts[folder_id_to_name[file.folder_id]] += 1
        return {"counts": counts, "total_files": total_files, "total_size": total_size}


# ── Sync state helpers ────────────────────────────────────────────────────────

def get_sync_state(telegram_user_id: int) -> dict:
    with Session(engine) as s:
        row = s.get(SyncState, telegram_user_id)
        if row:
            return {
                "last_sync_at": row.last_sync_at.timestamp() if row.last_sync_at else 0.0,
                "newest_msg_id": row.newest_msg_id,
            }
        return {"last_sync_at": 0.0, "newest_msg_id": 0}


def update_sync_state(telegram_user_id: int, last_sync_at: Optional[float] = None, newest_msg_id: Optional[int] = None):
    with Session(engine) as s:
        row = s.get(SyncState, telegram_user_id)
        if not row:
            row = SyncState(telegram_user_id=telegram_user_id)
        if last_sync_at is not None:
            row.last_sync_at = datetime.utcfromtimestamp(last_sync_at)
        if newest_msg_id is not None and newest_msg_id > (row.newest_msg_id or 0):
            row.newest_msg_id = newest_msg_id
        s.merge(row)
        s.commit()


# ── Delete all user data ──────────────────────────────────────────────────────

def delete_all_user_data(telegram_user_id: int):
    _cred_cache.pop(telegram_user_id, None)
    _session_cache.pop(telegram_user_id, None)
    with Session(engine) as s:
        # FileChunk has no telegram_user_id column — it's reached via the user's sessions —
        # and must be cleared before UploadSession/TelegramFile to satisfy their FKs.
        session_ids = s.exec(select(UploadSession.id).where(UploadSession.telegram_user_id == telegram_user_id)).all()
        if session_ids:
            chunks = s.exec(select(FileChunk).where(FileChunk.session_id.in_(session_ids))).all()
            for c in chunks:
                s.delete(c)
            s.flush()
        # SQLAlchemy doesn't infer cross-table delete ordering from plain FK columns (no
        # relationship() is declared on these models), so each model is flushed before the
        # next to respect upload_sessions -> files -> folders dependency order.
        for model in (UploadSession, TelegramFile, Folder, SyncState, UserSettings, UserTelegramSession, UserApiCredentials, User):
            rows = s.exec(select(model).where(
                getattr(model, "telegram_user_id") == telegram_user_id
            )).all()
            for row in rows:
                s.delete(row)
            s.flush()
        s.commit()


# ── Upload session / chunk helpers ────────────────────────────────────────────

def create_upload_session(
    telegram_user_id: int, filename: str, total_size: int, mime_type: str,
    folder_id: Optional[UUID], chunk_size: int, total_chunks: int,
) -> UploadSession:
    with Session(engine) as s:
        session = UploadSession(
            telegram_user_id=telegram_user_id,
            filename=filename,
            total_size=total_size,
            mime_type=mime_type,
            folder_id=folder_id,
            chunk_size=chunk_size,
            total_chunks=total_chunks,
        )
        s.add(session)
        s.commit()
        s.refresh(session)
        return session


def get_upload_session(session_id: UUID) -> Optional[UploadSession]:
    with Session(engine) as s:
        return s.get(UploadSession, session_id)


def get_stale_upload_sessions(older_than: datetime, status: str = "uploading") -> list[UploadSession]:
    with Session(engine) as s:
        return s.exec(select(UploadSession).where(
            UploadSession.status == status,
            UploadSession.updated_at < older_than,
        )).all()


def get_active_upload_sessions(telegram_user_id: int) -> list[dict]:
    """Every upload session still in progress for this user — lets the frontend reattach
    its progress widget to a chunked upload whose background Telegram push survives a
    page refresh, even though the browser-side JS driving it does not."""
    with Session(engine) as s:
        stmt = (
            select(UploadSession, Folder.name.label("folder_name"))
            .outerjoin(Folder, UploadSession.folder_id == Folder.id)
            .where(
                UploadSession.telegram_user_id == telegram_user_id,
                UploadSession.status == "uploading",
            )
            .order_by(UploadSession.created_at.desc())
        )
        rows = s.exec(stmt).all()
        return [
            {
                "session_id": str(session.id),
                "filename": session.filename,
                "folder_name": folder_name,
                "next_part_number": session.next_part_number,
                "total_chunks": session.total_chunks,
                "chunk_size": session.chunk_size,
                "bytes_uploaded": session.bytes_uploaded,
                "total_size": session.total_size,
            }
            for session, folder_name in rows
        ]


def get_confirmed_chunks(session_id: UUID) -> list[FileChunk]:
    with Session(engine) as s:
        return s.exec(select(FileChunk).where(
            FileChunk.session_id == session_id
        ).order_by(FileChunk.part_number)).all()


def get_confirmed_chunk(session_id: UUID, part_number: int) -> Optional[FileChunk]:
    with Session(engine) as s:
        return s.exec(select(FileChunk).where(
            FileChunk.session_id == session_id,
            FileChunk.part_number == part_number,
        )).first()


def record_file_chunk(session_id: UUID, part_number: int, telegram_message_id: int, size: int, sha256: str) -> FileChunk:
    """Idempotent: re-recording an already-confirmed part returns the existing row untouched."""
    with Session(engine) as s:
        existing = s.exec(select(FileChunk).where(
            FileChunk.session_id == session_id,
            FileChunk.part_number == part_number,
        )).first()
        if existing:
            return existing

        chunk = FileChunk(
            session_id=session_id, part_number=part_number,
            telegram_message_id=telegram_message_id, size=size, sha256=sha256,
        )
        s.add(chunk)

        session = s.get(UploadSession, session_id)
        if session:
            session.bytes_uploaded = (session.bytes_uploaded or 0) + size
            session.next_part_number = max(session.next_part_number, part_number + 1)
            session.updated_at = datetime.utcnow()
            s.add(session)

        s.commit()
        s.refresh(chunk)
        return chunk


def finalize_chunked_file(
    session_id: UUID, filename: str, total_size: int, mime_type: str,
    category: str, folder_id: Optional[UUID], chunk_count: int, content_signature: str,
) -> TelegramFile:
    """Create the logical TelegramFile row, attach all of the session's chunks to it, and mark the session completed.
    Idempotent: calling this again for an already-completed session returns the existing file row."""
    with Session(engine) as s:
        session = s.get(UploadSession, session_id)
        if session.file_id:
            return s.get(TelegramFile, session.file_id)

        file_row = TelegramFile(
            telegram_user_id=session.telegram_user_id,
            folder_id=folder_id,
            telegram_message_id=None,
            filename=filename,
            mime_type=mime_type,
            file_size=total_size,
            category=category,
            uploaded_at=datetime.utcnow(),
            is_chunked=True,
            chunk_count=chunk_count,
            content_signature=content_signature,
        )
        s.add(file_row)
        s.flush()

        chunks = s.exec(select(FileChunk).where(FileChunk.session_id == session_id)).all()
        for chunk in chunks:
            chunk.file_id = file_row.id
            s.add(chunk)

        session.status = "completed"
        session.file_id = file_row.id
        session.updated_at = datetime.utcnow()
        s.add(session)

        s.commit()
        s.refresh(file_row)
        return file_row


def abort_upload_session(session_id: UUID) -> list[int]:
    """Delete the session and its chunk rows; returns the Telegram message ids the caller must clean up."""
    with Session(engine) as s:
        chunks = s.exec(select(FileChunk).where(FileChunk.session_id == session_id)).all()
        message_ids = [c.telegram_message_id for c in chunks]
        for chunk in chunks:
            s.delete(chunk)
        session = s.get(UploadSession, session_id)
        if session:
            session.status = "aborted"
            session.updated_at = datetime.utcnow()
            s.add(session)
        s.commit()
        return message_ids


def get_file_chunks_ordered(file_id: UUID) -> list[FileChunk]:
    with Session(engine) as s:
        return s.exec(select(FileChunk).where(
            FileChunk.file_id == file_id
        ).order_by(FileChunk.part_number)).all()


# ── Scan-based chunk recovery ─────────────────────────────────────────────────
# Disaster recovery only: reconstructing a chunked file's grouping from raw Telegram
# messages when Postgres has no record of it (fresh device, DB wipe). See
# backend.chunk_upload.parse_chunk_caption for how a group is recognized during a scan.

def get_user_session_ids(telegram_user_id: int) -> set[UUID]:
    """Every upload-session id already known to Postgres for this user — used to skip
    re-processing chunk-part messages that are already properly tracked."""
    with Session(engine) as s:
        return set(s.exec(select(UploadSession.id).where(UploadSession.telegram_user_id == telegram_user_id)).all())


def recover_chunked_file(
    telegram_user_id: int, filename: str, total_size: int, mime_type: str,
    category: str, parts: list[tuple[int, int, int]],
) -> TelegramFile:
    """Reconstructs a chunked file purely from raw Telegram messages. `parts` is
    (part_number, telegram_message_id, size) for every part, already verified complete
    by the caller. Synthesizes a completed UploadSession to satisfy FileChunk's FK, since
    the original session row is gone. Per-chunk sha256/content_signature can't be recovered
    without re-downloading and re-hashing every part, so they're left blank — grouping,
    ordering, and retrieval is what this recovers, not the upload-time integrity guarantee.
    """
    total_chunks = len(parts)
    non_final_sizes = [size for _, _, size in parts[:-1]]
    chunk_size = max(non_final_sizes) if non_final_sizes else total_size

    with Session(engine) as s:
        session = UploadSession(
            telegram_user_id=telegram_user_id, filename=filename, total_size=total_size,
            mime_type=mime_type, folder_id=None, chunk_size=chunk_size,
            total_chunks=total_chunks, next_part_number=total_chunks + 1,
            bytes_uploaded=total_size, status="completed",
        )
        s.add(session)
        s.flush()

        file_row = TelegramFile(
            telegram_user_id=telegram_user_id, folder_id=None, telegram_message_id=None,
            filename=filename, mime_type=mime_type, file_size=total_size, category=category,
            uploaded_at=datetime.utcnow(), is_chunked=True, chunk_count=total_chunks,
            content_signature=None,
        )
        s.add(file_row)
        s.flush()

        session.file_id = file_row.id
        s.add(session)

        for part_number, message_id, size in parts:
            s.add(FileChunk(
                session_id=session.id, file_id=file_row.id, part_number=part_number,
                telegram_message_id=message_id, size=size, sha256="",
            ))

        s.commit()
        s.refresh(file_row)
        return file_row
