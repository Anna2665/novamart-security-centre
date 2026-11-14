from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..deps import Principal, get_principal, require
from ..services import backup, state

router = APIRouter(prefix="/backup", tags=["backup"])


@router.get("")
def status(p: Principal = Depends(get_principal)):
    return backup.status()


class CreateIn(BaseModel):
    label: str = Field(default="Manual snapshot", max_length=100)


@router.post("/create")
def create(body: CreateIn, p: Principal = Depends(require("backup:manage"))):
    try:
        return backup.create_backup(body.label, "manual", p.username)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e


@router.post("/{bid}/verify")
def verify(bid: str, p: Principal = Depends(require("backup:manage"))):
    try:
        return backup.verify_backup(bid, p.username)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e


@router.post("/{bid}/corrupt")
def corrupt(bid: str, p: Principal = Depends(require("backup:manage"))):
    try:
        return backup.corrupt_backup(bid, p.username)
    except (KeyError, TypeError) as e:
        raise HTTPException(404, "backup not found") from e


@router.post("/ransomware")
def ransomware(p: Principal = Depends(require("backup:manage"))):
    return backup.ransomware_impact(p.username)


class RestoreIn(BaseModel):
    backup_id: str | None = None


@router.post("/restore")
def restore(body: RestoreIn, p: Principal = Depends(require("backup:restore"))):
    try:
        return backup.restore(body.backup_id, p.username)
    except ValueError as e:
        raise HTTPException(409, str(e)) from e
