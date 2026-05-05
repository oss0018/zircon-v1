"""
Threat Intelligence Dashboard API (Variant B — manifest-driven, read-only grid).

Endpoints:
  GET    /                           — list all TI dashboards (with widgets)
  GET    /{dashboard_id}             — get a single dashboard with all widgets
  POST   /                           — create a new dashboard
  PUT    /{dashboard_id}             — update dashboard metadata
  DELETE /{dashboard_id}             — delete dashboard (and its widgets)
  GET    /{dashboard_id}/widgets     — list widgets for a dashboard
  POST   /{dashboard_id}/widgets     — add a widget to a dashboard
  PUT    /{dashboard_id}/widgets/{widget_id}  — update widget
  DELETE /{dashboard_id}/widgets/{widget_id}  — delete widget
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.api.auth import get_current_user
from app.database import get_db
from app.models import TIDashboard, TIWidget, User
from app.schemas import (
    TIDashboardCreate, TIDashboardOut,
    TIWidgetCreate, TIWidgetOut,
)

router = APIRouter()


# ── Dashboard CRUD ────────────────────────────────────────────────────────

@router.get("", response_model=List[TIDashboardOut])
async def list_dashboards(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return all TI dashboards with their widgets."""
    result = await db.execute(
        select(TIDashboard)
        .options(selectinload(TIDashboard.widgets))
        .order_by(TIDashboard.id)
    )
    return result.scalars().unique().all()


@router.get("/{dashboard_id}", response_model=TIDashboardOut)
async def get_dashboard(
    dashboard_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Return a single TI dashboard with all its widgets."""
    result = await db.execute(
        select(TIDashboard)
        .options(selectinload(TIDashboard.widgets))
        .where(TIDashboard.id == dashboard_id)
    )
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    return dashboard


@router.post("", response_model=TIDashboardOut, status_code=201)
async def create_dashboard(
    data: TIDashboardCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Create a new TI dashboard."""
    existing = await db.execute(
        select(TIDashboard).where(TIDashboard.slug == data.slug)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Slug already exists")
    dashboard = TIDashboard(
        name=data.name,
        slug=data.slug,
        scope=data.scope,
        is_default=data.is_default,
    )
    db.add(dashboard)
    await db.commit()
    # Reload with widgets relationship
    result = await db.execute(
        select(TIDashboard)
        .options(selectinload(TIDashboard.widgets))
        .where(TIDashboard.id == dashboard.id)
    )
    return result.scalar_one()


@router.put("/{dashboard_id}", response_model=TIDashboardOut)
async def update_dashboard(
    dashboard_id: int,
    data: TIDashboardCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Update TI dashboard metadata."""
    result = await db.execute(
        select(TIDashboard)
        .options(selectinload(TIDashboard.widgets))
        .where(TIDashboard.id == dashboard_id)
    )
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    # Check slug uniqueness if it changed
    if dashboard.slug != data.slug:
        slug_check = await db.execute(
            select(TIDashboard).where(TIDashboard.slug == data.slug)
        )
        if slug_check.scalar_one_or_none():
            raise HTTPException(status_code=409, detail="Slug already exists")
    dashboard.name = data.name
    dashboard.slug = data.slug
    dashboard.scope = data.scope
    dashboard.is_default = data.is_default
    await db.commit()
    await db.refresh(dashboard)
    return dashboard


@router.delete("/{dashboard_id}", status_code=204)
async def delete_dashboard(
    dashboard_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Delete a TI dashboard and all its widgets."""
    result = await db.execute(
        select(TIDashboard).where(TIDashboard.id == dashboard_id)
    )
    dashboard = result.scalar_one_or_none()
    if not dashboard:
        raise HTTPException(status_code=404, detail="Dashboard not found")
    await db.delete(dashboard)
    await db.commit()


# ── Widget CRUD ───────────────────────────────────────────────────────────

@router.get("/{dashboard_id}/widgets", response_model=List[TIWidgetOut])
async def list_widgets(
    dashboard_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """List widgets for a given dashboard."""
    result = await db.execute(
        select(TIWidget)
        .where(TIWidget.dashboard_id == dashboard_id)
        .order_by(TIWidget.id)
    )
    return result.scalars().all()


@router.post("/{dashboard_id}/widgets", response_model=TIWidgetOut, status_code=201)
async def add_widget(
    dashboard_id: int,
    data: TIWidgetCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Add a widget to a dashboard."""
    dash_result = await db.execute(
        select(TIDashboard).where(TIDashboard.id == dashboard_id)
    )
    if not dash_result.scalar_one_or_none():
        raise HTTPException(status_code=404, detail="Dashboard not found")
    widget = TIWidget(
        dashboard_id=dashboard_id,
        type=data.type,
        title=data.title,
        params_json=data.params_json,
        layout_json=data.layout_json,
    )
    db.add(widget)
    await db.commit()
    await db.refresh(widget)
    return widget


@router.put("/{dashboard_id}/widgets/{widget_id}", response_model=TIWidgetOut)
async def update_widget(
    dashboard_id: int,
    widget_id: int,
    data: TIWidgetCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Update a widget's type, title, params, or layout."""
    result = await db.execute(
        select(TIWidget).where(
            TIWidget.id == widget_id,
            TIWidget.dashboard_id == dashboard_id,
        )
    )
    widget = result.scalar_one_or_none()
    if not widget:
        raise HTTPException(status_code=404, detail="Widget not found")
    widget.type = data.type
    widget.title = data.title
    widget.params_json = data.params_json
    widget.layout_json = data.layout_json
    await db.commit()
    await db.refresh(widget)
    return widget


@router.delete("/{dashboard_id}/widgets/{widget_id}", status_code=204)
async def delete_widget(
    dashboard_id: int,
    widget_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Delete a widget from a dashboard."""
    result = await db.execute(
        select(TIWidget).where(
            TIWidget.id == widget_id,
            TIWidget.dashboard_id == dashboard_id,
        )
    )
    widget = result.scalar_one_or_none()
    if not widget:
        raise HTTPException(status_code=404, detail="Widget not found")
    await db.delete(widget)
    await db.commit()
