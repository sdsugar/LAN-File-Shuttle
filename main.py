import os
import sys
import socket
import secrets
import shutil
import urllib.parse
from datetime import datetime
from typing import Dict, List, Optional, Set

import uvicorn
from fastapi import FastAPI, Request, Form, UploadFile, File, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse, FileResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

try:
    import zipstream
except ImportError:
    zipstream = None

try:
    import qrcode
    import io
except ImportError:
    qrcode = None


# ==========================================
# 局域网 IP 与网络辅助
# ==========================================
def get_all_lan_ips() -> List[str]:
    """获取本机所有局域网 IPv4 地址列表，优先将最通用的局域网 IP 置顶"""
    ips: Set[str] = set()
    # 尝试通过 UDP socket 获取与外网/网关通信的默认 IP
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            best_ip = s.getsockname()[0]
            if best_ip and not best_ip.startswith("127."):
                ips.add(best_ip)
    except Exception:
        best_ip = None

    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                ips.add(ip)
    except Exception:
        pass

    sorted_ips = list(ips)
    if best_ip and best_ip in sorted_ips:
        sorted_ips.remove(best_ip)
        sorted_ips.insert(0, best_ip)
    
    if not sorted_ips:
        sorted_ips = ["127.0.0.1"]
    return sorted_ips


# ==========================================
# 会话与内存存储管理（纯内存无传统数据库）
# ==========================================
class SessionData:
    def __init__(
        self,
        token: str,
        storage_dir: str,
        name: str = "",
        permissions: Optional[List[str]] = None,
        read_only: bool = False
    ):
        self.token = token
        self.storage_dir = os.path.abspath(os.path.normpath(storage_dir))
        self.name = name or os.path.basename(self.storage_dir) or "文件传输目录"
        self.created_at = datetime.now()
        self.active_connections: Set[WebSocket] = set()

        # 权限支持多选：upload, browse, download
        valid_perms = {"upload", "browse", "download"}
        if permissions is not None:
            self.permissions = {p for p in permissions if p in valid_perms}
        else:
            if read_only:
                self.permissions = {"browse", "download"}
            else:
                self.permissions = {"upload", "browse", "download"}

    @property
    def can_upload(self) -> bool:
        return "upload" in self.permissions

    @property
    def can_browse(self) -> bool:
        return "browse" in self.permissions

    @property
    def can_download(self) -> bool:
        return "download" in self.permissions

    @property
    def read_only(self) -> bool:
        return not self.can_upload

    def to_dict(self, include_storage_dir: bool = True):
        d = {
            "token": self.token,
            "name": self.name,
            "permissions": sorted(list(self.permissions)),
            "can_upload": self.can_upload,
            "can_browse": self.can_browse,
            "can_download": self.can_download,
            "read_only": not self.can_upload,  # 向后兼容
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "online_count": len(self.active_connections),
        }
        if include_storage_dir:
            d["storage_dir"] = self.storage_dir
        return d


# 全局内存会话表：token -> SessionData
SESSIONS: Dict[str, SessionData] = {}


# ==========================================
# WebSocket 连接管理器
# ==========================================
class ConnectionManager:
    @staticmethod
    async def connect(token: str, websocket: WebSocket):
        await websocket.accept()
        session = SESSIONS.get(token)
        if session:
            session.active_connections.add(websocket)
            await ConnectionManager.broadcast(token, {
                "type": "online_count",
                "count": len(session.active_connections)
            })

    @staticmethod
    def disconnect(token: str, websocket: WebSocket):
        session = SESSIONS.get(token)
        if session and websocket in session.active_connections:
            session.active_connections.remove(websocket)

    @staticmethod
    async def broadcast(token: str, message: dict):
        session = SESSIONS.get(token)
        if not session:
            return
        dead_connections = []
        for ws in list(session.active_connections):
            try:
                await ws.send_json(message)
            except Exception:
                dead_connections.append(ws)
        for dead_ws in dead_connections:
            if dead_ws in session.active_connections:
                session.active_connections.remove(dead_ws)


# ==========================================
# 辅助工具函数
# ==========================================
def format_size(size_bytes: int) -> str:
    """人类可读的文件大小格式化"""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"


def safe_resolve_path(base_dir: str, subpath: str) -> str:
    """
    严格校验相对路径，避免跨目录穿越漏洞 (Directory Traversal)。
    如果路径不安全或超出 base_dir，抛出 ValueError。
    """
    base_dir = os.path.abspath(os.path.normpath(base_dir))
    clean_subpath = (subpath or "").replace("\\", "/").strip().lstrip("/")
    parts = [p for p in clean_subpath.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        raise ValueError("检测到非法路径遍历字符 (..)")

    resolved = os.path.abspath(os.path.normpath(os.path.join(base_dir, *parts)))
    
    # 严格确保在 base_dir 范围之内
    common = os.path.commonpath([base_dir, resolved])
    if os.path.normcase(common) != os.path.normcase(base_dir):
        raise ValueError("访问路径越界超出根目录")
    return resolved


MAX_FILE_SIZE = 1 * 1024 * 1024 * 1024  # 1 GB 限制
MAX_ZIP_SIZE = 1 * 1024 * 1024 * 1024   # 1 GB 压缩打包限制


def is_host_request(request: Request) -> bool:
    """
    判断请求是否来自于本机（主机管理员）
    支持 127.0.0.1、::1、localhost、testclient 以及本机网卡分配的所有局域网 IP
    """
    if not request.client or not request.client.host:
        return False
    client_ip = request.client.host
    if client_ip.startswith("::ffff:"):
        client_ip = client_ip[7:]
    if client_ip in {"127.0.0.1", "::1", "localhost", "testclient"}:
        return True
    try:
        local_lan_ips = set(get_all_lan_ips())
        if client_ip in local_lan_ips:
            return True
    except Exception:
        pass
    return False


# ==========================================
# FastAPI 应用实例初始化
# ==========================================
app = FastAPI(title="局域网点对点临时文件传输工具", version="1.0.0")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DOWNLOAD_DIR = os.path.join(BASE_DIR, "download")
os.makedirs(DEFAULT_DOWNLOAD_DIR, exist_ok=True)
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)
templates = Jinja2Templates(directory=TEMPLATES_DIR)


# ==========================================
# HTTP 页面路由
# ==========================================
@app.get("/", response_class=HTMLResponse)
async def index_page(request: Request):
    """主机启动引导页及会话管理控制台 (非本机访问时展示访客引导页)"""
    lan_ips = get_all_lan_ips()
    is_host = is_host_request(request)

    if not is_host:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "view_mode": "guest",
                "is_host": False,
                "lan_ips": lan_ips,
            }
        )

    primary_ip = lan_ips[0] if lan_ips else "127.0.0.1"
    host_header = request.headers.get("host", f"{primary_ip}:8000")
    base_url = f"http://{host_header}"

    # 快捷推荐目录（方便用户一键填入）
    presets = [
        {"name": "默认 download 目录", "path": DEFAULT_DOWNLOAD_DIR},
        {"name": "当前项目工作目录", "path": BASE_DIR},
        {"name": "系统用户下载目录", "path": os.path.join(os.path.expanduser("~"), "Downloads")},
        {"name": "系统用户桌面目录", "path": os.path.join(os.path.expanduser("~"), "Desktop")},
    ]

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "view_mode": "host",
            "is_host": True,
            "lan_ips": lan_ips,
            "base_url": base_url,
            "presets": presets,
            "default_path": DEFAULT_DOWNLOAD_DIR,
        }
    )


@app.get("/s/{token}", response_class=HTMLResponse)
async def session_page(request: Request, token: str):
    """专属会话工作台页面"""
    is_host = is_host_request(request)
    session = SESSIONS.get(token)
    if not session:
        return templates.TemplateResponse(
            request=request,
            name="index.html",
            context={
                "view_mode": "not_found",
                "is_host": is_host,
                "message": "该传输会话不存在或已结束（服务重启或会话被关闭）。请向主机创建者索取最新专属链接。"
            },
            status_code=404
        )

    host_header = request.headers.get("host", "localhost:8000")
    share_url = f"http://{host_header}/s/{token}"

    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "view_mode": "workspace",
            "token": token,
            "session": session.to_dict(include_storage_dir=is_host),
            "share_url": share_url,
            "is_host": is_host,
        }
    )


# ==========================================
# 后端 API 路由
# ==========================================
@app.post("/api/validate_path")
async def validate_path(
    request: Request,
    path: str = Form(...),
    create_if_missing: bool = Form(False)
):
    """校验目录有效性，并可选是否自动创建（仅限本机主机管理员）"""
    if not is_host_request(request):
        raise HTTPException(status_code=403, detail="无权操作：该接口仅限本机主机管理员调用")

    clean_path = path.strip()
    if not clean_path:
        return {"valid": False, "msg": "路径不能为空"}

    abs_path = os.path.abspath(clean_path)
    if not os.path.exists(abs_path):
        if create_if_missing:
            try:
                os.makedirs(abs_path, exist_ok=True)
            except Exception as e:
                return {"valid": False, "msg": f"创建目录失败: {str(e)}", "path": abs_path}
        else:
            return {"valid": False, "exists": False, "msg": "目录不存在，可勾选自动创建", "path": abs_path}

    if not os.path.isdir(abs_path):
        return {"valid": False, "msg": "所填路径不是一个有效的文件夹", "path": abs_path}

    # 测试是否具备可写权限
    test_file = os.path.join(abs_path, f".lan_write_test_{secrets.token_hex(4)}.tmp")
    try:
        with open(test_file, "w") as f:
            f.write("ok")
        os.remove(test_file)
        return {"valid": True, "exists": True, "writable": True, "path": abs_path, "msg": "目录有效且可写入"}
    except Exception as e:
        return {"valid": False, "exists": True, "writable": False, "msg": f"目录无写入权限: {str(e)}", "path": abs_path}


@app.post("/api/create_session")
async def create_session(
    request: Request,
    path: Optional[str] = Form(None),
    name: str = Form(""),
    custom_token: Optional[str] = Form(None),
    permissions: Optional[str] = Form(None),
    allow_upload: Optional[bool] = Form(None),
    allow_browse: Optional[bool] = Form(None),
    allow_download: Optional[bool] = Form(None),
    read_only: bool = Form(False),
    auto_create: bool = Form(True)
):
    """创建并绑定新会话，支持设置多选权限：上传、浏览、下载（仅限本机主机管理员）"""
    if not is_host_request(request):
        raise HTTPException(status_code=403, detail="无权操作：创建传输会话仅限本机主机管理员调用")

    clean_path = (path or "").strip()
    if not clean_path:
        clean_path = DEFAULT_DOWNLOAD_DIR

    abs_path = os.path.abspath(clean_path)
    if not os.path.exists(abs_path):
        if auto_create:
            try:
                os.makedirs(abs_path, exist_ok=True)
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"自动创建目录失败: {str(e)}")
        else:
            raise HTTPException(status_code=400, detail="指定目录不存在")

    if not os.path.isdir(abs_path):
        raise HTTPException(status_code=400, detail="目标路径必须为文件夹")

    # 解析多选权限
    perms = []
    if permissions is not None and isinstance(permissions, str):
        clean_perms = [p.strip().lower() for p in permissions.split(",") if p.strip()]
        perms = [p for p in clean_perms if p in {"upload", "browse", "download"}]
        if not perms:
            raise HTTPException(status_code=400, detail="至少必须勾选一项权限（上传、浏览或下载）")
    elif any(x is not None for x in [allow_upload, allow_browse, allow_download]):
        if allow_upload: perms.append("upload")
        if allow_browse: perms.append("browse")
        if allow_download: perms.append("download")
        if not perms:
            raise HTTPException(status_code=400, detail="至少必须勾选一项权限（上传、浏览或下载）")
    else:
        if read_only:
            perms = ["browse", "download"]
        else:
            perms = ["upload", "browse", "download"]

    # 生成简短局域网专属 Token (支持自定义，若未填则默认 4 位纯数字取件码)
    clean_custom = (custom_token or "").strip()
    if clean_custom:
        valid_chars = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        if not all(c in valid_chars for c in clean_custom):
            raise HTTPException(status_code=400, detail="自定义传输码仅支持英文字母、数字、下划线与短横线")
        if len(clean_custom) > 20:
            raise HTTPException(status_code=400, detail="自定义传输码长度不能超过 20 位")
        if clean_custom in SESSIONS:
            raise HTTPException(status_code=400, detail=f"传输码【{clean_custom}】已被现有会话占用，请更换")
        token = clean_custom
    else:
        # 默认生成 4 位纯数字传输码 (例如 8821)，极简好记，手机容易输入
        token = ""
        for _ in range(200):
            candidate = str(secrets.randbelow(9000) + 1000)
            if candidate not in SESSIONS:
                token = candidate
                break
        if not token:
            token = secrets.token_hex(2)

    session = SessionData(
        token=token,
        storage_dir=abs_path,
        name=name,
        permissions=perms
    )
    SESSIONS[token] = session

    lan_ips = get_all_lan_ips()
    primary_ip = lan_ips[0] if lan_ips else "127.0.0.1"
    host_header = request.headers.get("host", f"{primary_ip}:8000")
    share_url = f"http://{host_header}/s/{token}"

    return {
        "status": "success",
        "token": token,
        "share_url": share_url,
        "session": session.to_dict(include_storage_dir=True)
    }


@app.get("/api/sessions")
async def list_sessions(request: Request):
    """获取所有当前活动会话（仅限本机主机管理员）"""
    if not is_host_request(request):
        raise HTTPException(status_code=403, detail="无权操作：会话管理列表仅限本机主机管理员查看")
    return [s.to_dict(include_storage_dir=True) for s in SESSIONS.values()]


@app.delete("/api/session/{token}")
async def close_session(request: Request, token: str):
    """关闭/移除会话（仅限本机主机管理员）"""
    if not is_host_request(request):
        raise HTTPException(status_code=403, detail="无权操作：关闭传输会话仅限本机主机管理员操作")
    if token in SESSIONS:
        session = SESSIONS.pop(token)
        # 通知该会话的所有在线客户端
        for ws in list(session.active_connections):
            try:
                await ws.send_json({"type": "session_closed", "msg": "会话已关闭"})
                await ws.close()
            except Exception:
                pass
        return {"status": "success", "msg": "会话已关闭"}
    raise HTTPException(status_code=404, detail="会话不存在")


@app.post("/api/session/{token}/permissions")
async def update_session_permissions(
    request: Request,
    token: str,
    permissions: Optional[str] = Form(""),
):
    """修改已生成会话的权限（仅限本机主机管理员）"""
    if not is_host_request(request):
        raise HTTPException(status_code=403, detail="无权操作：修改权限仅限本机主机管理员操作")

    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")

    clean_perms = [p.strip().lower() for p in (permissions or "").split(",") if p.strip()]
    valid_perms = {p for p in clean_perms if p in {"upload", "browse", "download"}}
    if not valid_perms:
        raise HTTPException(status_code=400, detail="至少必须保留一项权限（上传、浏览或下载）")

    session.permissions = valid_perms

    # 通过 WebSocket 实时向该会话所有在线客户端广播权限变更
    await ConnectionManager.broadcast(token, {
        "type": "permissions_updated",
        "permissions": sorted(list(session.permissions)),
        "can_upload": session.can_upload,
        "can_browse": session.can_browse,
        "can_download": session.can_download,
        "msg": "主机已调整本通道访问权限，页面将自动同步"
    })

    return {
        "status": "success",
        "msg": "权限修改成功",
        "session": session.to_dict(include_storage_dir=True)
    }


@app.get("/api/qrcode")
async def generate_qrcode(text: str):
    """即时生成二维码 PNG 字节流"""
    if not qrcode:
        raise HTTPException(status_code=500, detail="qrcode 依赖未就绪")
    
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=2,
    )
    qr.add_data(text)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#1e293b", back_color="#ffffff")
    
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    buf.seek(0)
    return Response(content=buf.getvalue(), media_type="image/png")


@app.get("/api/files")
async def list_files(token: str, subpath: str = ""):
    """获取指定会话指定子目录下的文件与文件夹列表（需具备 browse 权限）"""
    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")

    if not session.can_browse:
        raise HTTPException(status_code=403, detail="该传输通道未开放文件浏览权限（收集箱模式）")

    try:
        target_dir = safe_resolve_path(session.storage_dir, subpath)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not os.path.exists(target_dir):
        raise HTTPException(status_code=404, detail="目标路径不存在")

    # 构建面包屑导航路径结构
    rel_from_base = os.path.relpath(target_dir, session.storage_dir).replace("\\", "/")
    if rel_from_base == ".":
        rel_from_base = ""

    breadcrumbs = [{"name": session.name or "根目录", "path": ""}]
    if rel_from_base:
        accum = []
        for part in rel_from_base.split("/"):
            accum.append(part)
            breadcrumbs.append({"name": part, "path": "/".join(accum)})

    parent_path = None
    if rel_from_base:
        parent_parts = rel_from_base.split("/")[:-1]
        parent_path = "/".join(parent_parts)

    items = []
    try:
        with os.scandir(target_dir) as entries:
            for entry in entries:
                try:
                    stat = entry.stat()
                    is_dir = entry.is_dir()
                    item_rel = (rel_from_base + "/" + entry.name) if rel_from_base else entry.name
                    item_rel = item_rel.lstrip("/")

                    items.append({
                        "name": entry.name,
                        "is_dir": is_dir,
                        "size": 0 if is_dir else stat.st_size,
                        "size_fmt": "-" if is_dir else format_size(stat.st_size),
                        "modified_at": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
                        "relative_path": item_rel
                    })
                except (PermissionError, FileNotFoundError):
                    continue
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"读取目录失败: {str(e)}")

    # 排序：文件夹置顶，其次按名称字母排序
    items.sort(key=lambda x: (not x["is_dir"], x["name"].lower()))

    return {
        "current_path": rel_from_base,
        "parent_path": parent_path,
        "breadcrumbs": breadcrumbs,
        "items": items,
        "permissions": session.to_dict()["permissions"],
        "can_upload": session.can_upload,
        "can_browse": session.can_browse,
        "can_download": session.can_download,
        "read_only": session.read_only
    }


@app.post("/api/upload")
async def upload_file(
    token: str,
    file: UploadFile = File(...),
    relative_path: str = Form("")
):
    """
    流式分块写入上传的文件（需具备 upload 权限）。
    支持文件夹上传时保留层级结构（通过 relative_path 传递）。
    """
    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")
    if not session.can_upload:
        raise HTTPException(status_code=403, detail="该传输通道未开放文件上传权限")

    # 获取相对路径（若为空则使用原始文件名）
    path_to_use = relative_path.strip() or file.filename or "uploaded_file"
    try:
        dest_path = safe_resolve_path(session.storage_dir, path_to_use)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"非法的文件路径: {str(e)}")

    # 确保目标文件夹存在
    os.makedirs(os.path.dirname(dest_path), exist_ok=True)

    # 流式分块写入物理磁盘，并累加大小校验不超过 1GB
    total_size = 0
    chunk_size = 1024 * 1024  # 1MB 块大小

    try:
        with open(dest_path, "wb") as buffer:
            while True:
                chunk = await file.read(chunk_size)
                if not chunk:
                    break
                total_size += len(chunk)
                if total_size > MAX_FILE_SIZE:
                    # 超过限制，删除不完整的文件并终止
                    buffer.close()
                    if os.path.exists(dest_path):
                        os.remove(dest_path)
                    raise HTTPException(
                        status_code=413,
                        detail=f"文件 '{file.filename}' 超过大小限制 (最大允许 1GB)"
                    )
                buffer.write(chunk)
    except HTTPException:
        raise
    except Exception as e:
        if os.path.exists(dest_path):
            try:
                os.remove(dest_path)
            except Exception:
                pass
        raise HTTPException(status_code=500, detail=f"写入文件失败: {str(e)}")
    finally:
        await file.close()

    # 上传成功，向该会话所有在线客户端广播通知静默刷新
    await ConnectionManager.broadcast(token, {
        "type": "file_uploaded",
        "filename": os.path.basename(dest_path),
        "size_fmt": format_size(total_size)
    })

    return {
        "status": "success",
        "filename": os.path.basename(dest_path),
        "size": total_size,
        "size_fmt": format_size(total_size)
    }


@app.get("/api/download")
async def download_file(token: str, relative_path: str):
    """单文件直接下载（需具备 download 权限）"""
    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")
    if not session.can_download:
        raise HTTPException(status_code=403, detail="该传输通道未开放文件下载权限")

    try:
        file_path = safe_resolve_path(session.storage_dir, relative_path)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not os.path.isfile(file_path):
        raise HTTPException(status_code=404, detail="文件不存在或不是普通文件")

    filename = os.path.basename(file_path)
    encoded_filename = urllib.parse.quote(filename)

    return FileResponse(
        path=file_path,
        media_type="application/octet-stream",
        filename=filename,
        headers={
            "Content-Disposition": f"attachment; filename=\"{encoded_filename}\"; filename*=UTF-8''{encoded_filename}"
        }
    )


@app.get("/api/download_zip")
async def download_folder_zip(token: str, subpath: str = ""):
    """
    文件夹打包即时流式下载（需具备 download 权限）：
    服务端使用 zipstream 在内存中边压缩边流式传输，零临时磁盘缓存！
    限制总大小 1GB 以内。
    """
    if not zipstream:
        raise HTTPException(status_code=500, detail="服务器未安装 zipstream 压缩流组件")

    session = SESSIONS.get(token)
    if not session:
        raise HTTPException(status_code=404, detail="会话不存在")
    if not session.can_download:
        raise HTTPException(status_code=403, detail="该传输通道未开放文件夹打包下载权限")

    try:
        folder_path = safe_resolve_path(session.storage_dir, subpath)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if not os.path.isdir(folder_path):
        raise HTTPException(status_code=400, detail="目标路径不是文件夹")

    # 预先扫描该目录总大小，确保不超过 1GB
    total_size = 0
    file_list = []
    for root, _, files in os.walk(folder_path):
        for f in files:
            abs_p = os.path.join(root, f)
            try:
                f_size = os.path.getsize(abs_p)
                total_size += f_size
                if total_size > MAX_ZIP_SIZE:
                    raise HTTPException(
                        status_code=413,
                        detail=f"打包文件夹总大小 ({format_size(total_size)}) 已超过 1GB 上限，请分别下载单文件"
                    )
                # 计算在 zip 中的相对归档路径
                rel_to_target = os.path.relpath(abs_p, folder_path).replace("\\", "/")
                file_list.append((abs_p, rel_to_target))
            except (PermissionError, FileNotFoundError):
                continue

    folder_name = os.path.basename(folder_path) or session.name or "archive"
    zip_name = f"{folder_name}.zip"
    encoded_zip_name = urllib.parse.quote(zip_name)

    # 内存流式 Zip 压缩器
    zs = zipstream.ZipStream()
    for abs_p, arcname in file_list:
        zs.add_path(abs_p, arcname=f"{folder_name}/{arcname}")

    return StreamingResponse(
        zs,
        media_type="application/zip",
        headers={
            "Content-Disposition": f"attachment; filename=\"{encoded_zip_name}\"; filename*=UTF-8''{encoded_zip_name}"
        }
    )


# ==========================================
# WebSocket 实时通信端点
# ==========================================
@app.websocket("/ws/{token}")
async def websocket_endpoint(websocket: WebSocket, token: str):
    """实时通信频道，通知文件变动、在线人数与状态"""
    session = SESSIONS.get(token)
    if not session:
        await websocket.close(code=1008)
        return

    await ConnectionManager.connect(token, websocket)
    try:
        while True:
            # 维持长连接与心跳
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ConnectionManager.disconnect(token, websocket)
        await ConnectionManager.broadcast(token, {
            "type": "online_count",
            "count": len(session.active_connections)
        })
    except Exception:
        ConnectionManager.disconnect(token, websocket)


# ==========================================
# 程序启动主入口
# ==========================================
def main():
    import argparse
    parser = argparse.ArgumentParser(description="局域网点对点临时文件传输工具")
    parser.add_argument("--host", default="0.0.0.0", help="监听主机地址 (默认 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8000, help="服务端口 (默认 8000)")
    args = parser.parse_args()

    lan_ips = get_all_lan_ips()
    primary_ip = lan_ips[0] if lan_ips else "127.0.0.1"

    try:
        if sys.platform.startswith("win"):
            sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

    print("=" * 66)
    print(" [LAN File Shuttle] 局域网点对点临时文件传输工具 已启动")
    print("=" * 66)
    print(f" * 本机访问地址:    http://127.0.0.1:{args.port}")
    print(f" * 局域网首选地址:  http://{primary_ip}:{args.port}")
    if len(lan_ips) > 1:
        print(" * 其他局域网 IP:")
        for ip in lan_ips[1:]:
            print(f"    - http://{ip}:{args.port}")
    print("-" * 66)
    print(" * 特性: 纯内存无数据库、防路径穿越、大文件流式传输、文件夹即时ZIP打包")
    print(" * 请在浏览器中打开上方地址配置并创建您的传输会话")
    print("=" * 66)

    uvicorn.run(app, host=args.host, port=args.port, log_level="info")


if __name__ == "__main__":
    main()
