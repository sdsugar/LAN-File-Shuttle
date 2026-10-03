import os
import sys
import shutil
import tempfile
import time
import requests

try:
    if sys.platform.startswith("win"):
        sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print(">>> [1] 测试主引导页 GET /")
    res = requests.get(f"{BASE_URL}/")
    assert res.status_code == 200, f"主页响应异常: {res.status_code}"
    assert "LAN File Shuttle" in res.text, "主页标题未找到"
    print("  ✓ 主页渲染通过")

    print("\n>>> [2] 测试目录校验接口 POST /api/validate_path")
    # 创建一个临时测试目录
    test_dir = tempfile.mkdtemp(prefix="lan_transfer_test_")
    try:
        # 测试存在且可写的有效目录
        res = requests.post(f"{BASE_URL}/api/validate_path", data={"path": test_dir})
        assert res.status_code == 200
        data = res.json()
        assert data["valid"] is True, f"有效目录校验失败: {data}"
        print(f"  ✓ 有效目录校验通过: {data['msg']}")

        # 测试不存在且不自动创建的目录
        fake_dir = os.path.join(test_dir, "non_existent_folder")
        res = requests.post(f"{BASE_URL}/api/validate_path", data={"path": fake_dir, "create_if_missing": "false"})
        data = res.json()
        assert data["valid"] is False and data.get("exists") is False
        print("  ✓ 不存在目录校验拦截通过")

        print("\n>>> [3] 测试会话创建接口 POST /api/create_session")
        res = requests.post(f"{BASE_URL}/api/create_session", data={
            "path": test_dir,
            "name": "自动化测试工作区",
            "read_only": "false",
            "auto_create": "true"
        })
        assert res.status_code == 200
        session_info = res.json()
        token = session_info["token"]
        assert token, "未返回会话 token"
        print(f"  ✓ 会话创建成功! Token: {token}, URL: {session_info['share_url']}")

        print("\n>>> [4] 测试专属工作台页面 GET /s/{token}")
        res = requests.get(f"{BASE_URL}/s/{token}")
        assert res.status_code == 200
        assert "自动化测试工作区" in res.text
        print("  ✓ 工作台页面加载通过")

        print("\n>>> [5] 测试二维码生成接口 GET /api/qrcode")
        res = requests.get(f"{BASE_URL}/api/qrcode", params={"text": session_info["share_url"]})
        assert res.status_code == 200
        assert res.headers["content-type"] == "image/png"
        assert len(res.content) > 100
        print("  ✓ 二维码 PNG 生成通过")

        print("\n>>> [6] 测试单文件上传 POST /api/upload")
        file_content = b"Hello, LAN File Shuttle! 1234567890"
        files = {"file": ("demo.txt", file_content, "text/plain")}
        res = requests.post(f"{BASE_URL}/api/upload", params={"token": token}, files=files, data={"relative_path": ""})
        assert res.status_code == 200
        up_data = res.json()
        assert up_data["status"] == "success"
        # 验证物理磁盘是否存在
        assert os.path.exists(os.path.join(test_dir, "demo.txt"))
        with open(os.path.join(test_dir, "demo.txt"), "rb") as f:
            assert f.read() == file_content
        print("  ✓ 单文件物理落盘与内容校验通过")

        print("\n>>> [7] 测试文件夹层级上传 POST /api/upload (多层相对路径)")
        nested_rel_path = "subfolder/level2/nested_doc.pdf"
        nested_content = b"%PDF-1.4 Mock PDF Content For Testing"
        files = {"file": ("nested_doc.pdf", nested_content, "application/pdf")}
        res = requests.post(f"{BASE_URL}/api/upload", params={"token": token}, files=files, data={"relative_path": nested_rel_path})
        assert res.status_code == 200
        # 验证嵌套目录和物理文件
        disk_nested = os.path.join(test_dir, "subfolder", "level2", "nested_doc.pdf")
        assert os.path.exists(disk_nested), f"嵌套文件未在物理磁盘找到: {disk_nested}"
        print("  ✓ 文件夹相对路径多层级自动建目录并落盘通过")

        print("\n>>> [8] 测试目录穿越安全拦截 (Path Traversal Protection)")
        bad_paths = ["../../evil.txt", "../outside.txt", "sub/../../../root.txt"]
        for bp in bad_paths:
            files = {"file": ("evil.txt", b"hack", "text/plain")}
            res = requests.post(f"{BASE_URL}/api/upload", params={"token": token}, files=files, data={"relative_path": bp})
            assert res.status_code == 400, f"路径遍历未被拦截: {bp} (code {res.status_code})"
        print("  ✓ 目录穿越安全防护全部通过拦截")

        print("\n>>> [9] 测试文件列表查询 GET /api/files")
        # 根目录列表
        res = requests.get(f"{BASE_URL}/api/files", params={"token": token, "subpath": ""})
        assert res.status_code == 200
        files_info = res.json()
        item_names = [it["name"] for it in files_info["items"]]
        assert "demo.txt" in item_names
        assert "subfolder" in item_names
        print(f"  ✓ 根目录浏览通过，包含子项: {item_names}")

        # 子目录列表
        res = requests.get(f"{BASE_URL}/api/files", params={"token": token, "subpath": "subfolder/level2"})
        assert res.status_code == 200
        sub_info = res.json()
        sub_names = [it["name"] for it in sub_info["items"]]
        assert "nested_doc.pdf" in sub_names
        print(f"  ✓ 子目录浏览与面包屑导航通过: {sub_names}")

        print("\n>>> [10] 测试单文件直接下载 GET /api/download")
        res = requests.get(f"{BASE_URL}/api/download", params={"token": token, "relative_path": "demo.txt"})
        assert res.status_code == 200
        assert res.content == file_content
        print("  ✓ 单文件下载内容比对完全一致")

        print("\n>>> [11] 测试文件夹即时内存 ZIP 打包流式下载 GET /api/download_zip")
        res = requests.get(f"{BASE_URL}/api/download_zip", params={"token": token, "subpath": ""})
        assert res.status_code == 200
        assert res.headers["content-type"] == "application/zip"
        zip_bytes = res.content
        assert len(zip_bytes) > 0
        # 验证下载到的 zip 内容
        import zipfile, io
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
        zip_namelist = zf.namelist()
        print(f"  ✓ 内存即时 ZIP 打包下载解包检验通过! 压缩包文件清单: {zip_namelist}")

        print("\n>>> [12] 测试会话管理列表与关闭会话 DELETE /api/session/{token}")
        res = requests.get(f"{BASE_URL}/api/sessions")
        assert res.status_code == 200
        assert any(s["token"] == token for s in res.json())
        
        del_res = requests.delete(f"{BASE_URL}/api/session/{token}")
        assert del_res.status_code == 200
        
        # 再次访问已关闭会话，应为 404
        after_res = requests.get(f"{BASE_URL}/s/{token}")
        assert after_res.status_code == 404
        print("  ✓ 会话注销与 404 失效阻断校验通过")

        print("\n>>> [13] 权限测试 A: 【仅上传模式】(upload only - 收集箱模式)")
        res = requests.post(f"{BASE_URL}/api/create_session", data={
            "path": test_dir, "name": "仅上传收集箱", "permissions": "upload"
        })
        assert res.status_code == 200
        s_up = res.json()["session"]
        assert s_up["can_upload"] is True and s_up["can_browse"] is False and s_up["can_download"] is False
        token_up = s_up["token"]
        
        # 允许上传
        up_res = requests.post(f"{BASE_URL}/api/upload", params={"token": token_up}, files={"file": ("box.txt", b"secret", "text/plain")})
        assert up_res.status_code == 200, "仅上传模式应允许上传"
        
        # 禁止浏览列表 (403)
        browse_res = requests.get(f"{BASE_URL}/api/files", params={"token": token_up})
        assert browse_res.status_code == 403, "仅上传模式禁止浏览列表"

        # 禁止下载 (403)
        dl_res = requests.get(f"{BASE_URL}/api/download", params={"token": token_up, "relative_path": "box.txt"})
        assert dl_res.status_code == 403, "仅上传模式禁止下载"
        print("  ✓ 【仅上传模式】测试通过：允许上传、阻断列表浏览(403)、阻断文件下载(403)")

        print("\n>>> [14] 权限测试 B: 【仅浏览模式】(browse only - 目录预览模式)")
        res = requests.post(f"{BASE_URL}/api/create_session", data={
            "path": test_dir, "name": "仅浏览预览", "permissions": "browse"
        })
        assert res.status_code == 200
        s_br = res.json()["session"]
        assert s_br["can_upload"] is False and s_br["can_browse"] is True and s_br["can_download"] is False
        token_br = s_br["token"]

        # 允许浏览
        browse_res = requests.get(f"{BASE_URL}/api/files", params={"token": token_br})
        assert browse_res.status_code == 200, "仅浏览模式应允许获取文件列表"

        # 禁止上传 (403)
        up_res = requests.post(f"{BASE_URL}/api/upload", params={"token": token_br}, files={"file": ("fail.txt", b"x", "text/plain")})
        assert up_res.status_code == 403, "仅浏览模式禁止上传"

        # 禁止下载 (403)
        dl_res = requests.get(f"{BASE_URL}/api/download", params={"token": token_br, "relative_path": "box.txt"})
        assert dl_res.status_code == 403, "仅浏览模式禁止下载"
        print("  ✓ 【仅浏览模式】测试通过：允许查看列表、阻断上传(403)、阻断下载(403)")

        print("\n>>> [15] 权限测试 C: 【仅浏览+仅下载模式】(browse,download - 只读资料分发)")
        res = requests.post(f"{BASE_URL}/api/create_session", data={
            "path": test_dir, "name": "资料分发", "permissions": "browse,download"
        })
        assert res.status_code == 200
        s_bd = res.json()["session"]
        assert s_bd["can_upload"] is False and s_bd["can_browse"] is True and s_bd["can_download"] is True
        token_bd = s_bd["token"]

        # 允许浏览和下载
        assert requests.get(f"{BASE_URL}/api/files", params={"token": token_bd}).status_code == 200
        assert requests.get(f"{BASE_URL}/api/download", params={"token": token_bd, "relative_path": "box.txt"}).status_code == 200
        
        # 禁止上传
        assert requests.post(f"{BASE_URL}/api/upload", params={"token": token_bd}, files={"file": ("fail.txt", b"x", "text/plain")}).status_code == 403
        print("  ✓ 【仅浏览+下载模式】测试通过：允许浏览、允许下载、阻断上传(403)")

        print("\n>>> [16] 权限测试 D: 【空权限拦截】")
        res1 = requests.post(f"{BASE_URL}/api/create_session", data={
            "path": test_dir, "name": "非法空权限A", "permissions": "none"
        })
        assert res1.status_code == 400, "显式无权限应被 400 拦截"

        res2 = requests.post(f"{BASE_URL}/api/create_session", data={
            "path": test_dir, "name": "非法空权限B",
            "allow_upload": "false", "allow_browse": "false", "allow_download": "false"
        })
        assert res2.status_code == 400, "全部关闭权限应被 400 拦截"
        print("  ✓ 【空权限拦截】测试通过：正确拒绝未勾选任何权限的会话创建请求")

        print("\n==========================================")
        print("🎉 全部 16 项端到端核心业务、安全与多选权限测试均 100% 通过！")
        print("==========================================")

    finally:
        # 清理测试文件夹
        if os.path.exists(test_dir):
            try:
                shutil.rmtree(test_dir, ignore_errors=True)
            except Exception:
                pass

if __name__ == "__main__":
    run_tests()
