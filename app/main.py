"""FastAPI 入口：规则差分与规则有效性审计页面及 JSON API。"""

from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .engine import ValidationFailure, analyze, analyze_audit
from .example_data import AUDIT_EXAMPLE_PAYLOAD, EXAMPLE_PAYLOAD

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="防火墙规则工作台",
    description="精确比对两份有序 IPv4/TCP 规则集（差分），并审计单份规则集中每条规则的真实生效区域（有效性审计）。",
    version="1.1.0",
)


class DiffRequest(BaseModel):
    old: str = Field(..., description="旧规则集 JSON 文本（数组，最多 20 条）")
    new: str = Field(..., description="新规则集 JSON 文本（数组，最多 20 条）")


class AuditRequest(BaseModel):
    rules: str = Field(..., description="有序规则集 JSON 文本（数组，最多 20 条）")


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/audit", include_in_schema=False)
def audit_page() -> FileResponse:
    return FileResponse(STATIC_DIR / "audit.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/api/example")
def get_example() -> JSONResponse:
    """提供可一键载入的重叠规则示例（差分页）。"""
    return JSONResponse(EXAMPLE_PAYLOAD)


@app.get("/api/audit/example")
def get_audit_example() -> JSONResponse:
    """提供可一键载入的遮蔽 / 冲突规则示例（审计页）。"""
    return JSONResponse(AUDIT_EXAMPLE_PAYLOAD)


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/analyze")
def post_analyze(req: DiffRequest) -> JSONResponse:
    try:
        result = analyze(req.old, req.new)
    except ValidationFailure as exc:
        # 输入无效：返回带位置的结构化错误，前端据此清除旧结果
        return JSONResponse(status_code=400,
                            content={"ok": False, "errors": exc.errors})
    return JSONResponse(content={"ok": True, "result": result})


@app.post("/api/audit")
def post_audit(req: AuditRequest) -> JSONResponse:
    try:
        result = analyze_audit(req.rules)
    except ValidationFailure as exc:
        # 输入无效：返回带位置的结构化错误，前端据此清除旧结果
        return JSONResponse(status_code=400,
                            content={"ok": False, "errors": exc.errors})
    return JSONResponse(content={"ok": True, "result": result})


@app.exception_handler(Exception)
def unhandled(_request, exc: Exception) -> JSONResponse:  # pragma: no cover
    return JSONResponse(status_code=500,
                        content={"ok": False, "errors": [
                            {"sheet": None, "field": None,
                             "message": f"服务器内部错误：{type(exc).__name__}: {exc}"}]})
