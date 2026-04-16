import hashlib
import shutil
from pathlib import Path
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
import aiofiles

from app.api.auth import get_current_user
from app.database import get_db
from app.models import User, File as FileModel, Project
from app.schemas import FileOut, FileUpdate, ProjectCreate, ProjectOut
from app.config import settings
from app.services.indexer import index_file, remove_from_index, compute_checksum

router = APIRouter()

UPLOADS_DIR = Path(settings.uploads_dir)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


# ── Projects ─────────────────────────────────────────────────────────────────

@router.get("/projects", response_model=List[ProjectOut])
async def list_projects(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(Project).order_by(Project.created_at.desc()))
    return result.scalars().all()


@router.post("/projects", response_model=ProjectOut)
async def create_project(data: ProjectCreate, db: AsyncSession = Depends(get_db),
                         _: User = Depends(get_current_user)):
    project = Project(name=data.name, description=data.description)
    db.add(project)
    await db.commit()
    await db.refresh(project)
    return project


@router.delete("/projects/{project_id}")
async def delete_project(project_id: int, db: AsyncSession = Depends(get_db),
                         _: User = Depends(get_current_user)):
    result = await db.execute(select(Project).where(Project.id == project_id))
    project = result.scalar_one_or_none()
    if not project:
        raise HTTPException(status_code=404, detail="Project not found")
    await db.delete(project)
    await db.commit()
    return {"ok": True}


# ── Files ─────────────────────────────────────────────────────────────────────

@router.post("/upload", response_model=FileOut)
async def upload_file(
    file: UploadFile = File(...),
    project_id: Optional[int] = None,
    tags: str = "",
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    try:
        UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
        dest = UPLOADS_DIR / file.filename
        # Avoid name collision
        counter = 1
        stem = Path(file.filename).stem
        suffix = Path(file.filename).suffix
        while dest.exists():
            dest = UPLOADS_DIR / f"{stem}_{counter}{suffix}"
            counter += 1

        content = await file.read()
        async with aiofiles.open(dest, "wb") as f:
            await f.write(content)

        checksum = hashlib.sha256(content).hexdigest()
        mime = file.content_type or ""

        db_file = FileModel(
            name=dest.name,
            original_name=file.filename,
            path=str(dest),
            size=len(content),
            mime_type=mime,
            project_id=project_id,
            checksum=checksum,
            tags=tags,
        )
        db.add(db_file)
        await db.commit()
        await db.refresh(db_file)

        # Index in background
        project_name = ""
        if project_id:
            res = await db.execute(select(Project).where(Project.id == project_id))
            proj = res.scalar_one_or_none()
            if proj:
                project_name = proj.name

        ok = await index_file(db_file.id, str(dest), dest.name, suffix.lstrip("."), project_name)
        if ok:
            db_file.indexed = True
            await db.commit()

        await db.refresh(db_file)
        return db_file
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/", response_model=List[FileOut])
async def list_files(
    skip: int = 0,
    limit: int = 50,
    project_id: Optional[int] = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    q = select(FileModel).order_by(FileModel.uploaded_at.desc()).offset(skip).limit(limit)
    if project_id is not None:
        q = q.where(FileModel.project_id == project_id)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/stats")
async def file_stats(db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    total = await db.scalar(select(func.count(FileModel.id)))
    indexed = await db.scalar(select(func.count(FileModel.id)).where(FileModel.indexed == True))
    total_size = await db.scalar(select(func.sum(FileModel.size)))
    return {"total": total or 0, "indexed": indexed or 0, "total_size": total_size or 0}


@router.get("/{file_id}", response_model=FileOut)
async def get_file(file_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    return f


@router.patch("/{file_id}", response_model=FileOut)
async def update_file(file_id: int, data: FileUpdate, db: AsyncSession = Depends(get_db),
                      _: User = Depends(get_current_user)):
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    if data.name is not None:
        f.name = data.name
    if data.tags is not None:
        f.tags = data.tags
    if data.project_id is not None:
        f.project_id = data.project_id
    await db.commit()
    await db.refresh(f)
    return f


@router.delete("/{file_id}")
async def delete_file(file_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    # Remove from disk
    try:
        Path(f.path).unlink(missing_ok=True)
    except Exception:
        pass
    await remove_from_index(file_id)
    await db.delete(f)
    await db.commit()
    return {"ok": True}


@router.post("/{file_id}/reindex")
async def reindex_file(file_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    ok = await index_file(f.id, f.path, f.name, Path(f.name).suffix.lstrip("."))
    if ok:
        f.indexed = True
        await db.commit()
    return {"ok": ok}


@router.get("/{file_id}/download")
async def download_file(file_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(get_current_user)):
    from fastapi.responses import FileResponse
    result = await db.execute(select(FileModel).where(FileModel.id == file_id))
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    path = Path(f.path)
    if not path.exists():
        raise HTTPException(status_code=404, detail="File not found on disk")
    return FileResponse(str(path), filename=f.original_name, media_type=f.mime_type or "application/octet-stream")
