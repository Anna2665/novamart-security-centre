from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..deps import Principal, get_principal, require
from ..services import incidents

router = APIRouter(prefix="/incidents", tags=["incidents"])


@router.get("")
def list_(p: Principal = Depends(get_principal)):
    return incidents.list_all()


@router.get("/{iid}")
def get(iid: int, p: Principal = Depends(get_principal)):
    try:
        return incidents.get(iid)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e


@router.post("/{iid}/tasks/{tid}/toggle")
def toggle(iid: int, tid: str, p: Principal = Depends(require("incident:manage"))):
    try:
        return incidents.toggle_task(iid, tid, p.username, p.jti)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e
    except ValueError as e:
        raise HTTPException(409, str(e)) from e


@router.post("/{iid}/advance")
def advance(iid: int, p: Principal = Depends(require("incident:manage"))):
    try:
        return incidents.advance(iid, p.username)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e
    except ValueError as e:
        raise HTTPException(409, str(e)) from e


class Notes(BaseModel):
    text: str = Field(max_length=4000)


@router.put("/{iid}/notes")
def notes(iid: int, body: Notes, p: Principal = Depends(require("incident:manage"))):
    try:
        return incidents.add_notes(iid, body.text, p.username)
    except KeyError as e:
        raise HTTPException(404, str(e)) from e
