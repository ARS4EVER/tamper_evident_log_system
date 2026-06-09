"""
防篡改审计日志系统 - Web用户界面

基于FastAPI构建的现代化Web界面，提供日志提交、查询、验证和审计功能。
"""

import os
import json
from datetime import datetime
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, Request, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

# 添加项目路径
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src import LogServer, ServerConfig, Auditor, AuditResult
from src.crypto import SignedTreeHead
from src.merkle import MerkleTree, InclusionProof, ConsistencyProof

# 全局服务器实例
storage_path = "./web_storage"
server_config = ServerConfig(storage_path=storage_path, sth_interval=10)
log_server = LogServer(server_config)
auditor = Auditor(log_server.public_key, storage_path)

# FastAPI应用配置
app = FastAPI(title="防篡改审计日志系统", description="Tamper-Evident Audit Log System")

# 模板和静态文件
from jinja2 import Environment, FileSystemLoader, select_autoescape

# 创建自定义 Jinja2 环境，避免缓存问题
jinja_env = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(['html', 'htm']),
    cache_size=0,
)

# 使用自定义环境创建模板引擎
templates = Jinja2Templates(env=jinja_env)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Pydantic模型
class LogEntry(BaseModel):
    data: str
    timestamp: Optional[int] = None

class VerifyRequest(BaseModel):
    index: int

class ConsistencyRequest(BaseModel):
    old_size: int

class AuditResultResponse(BaseModel):
    verified_items: int
    passed_items: int
    failed_items: int
    duration_ms: float
    details: List[Dict[str, Any]]

# 辅助函数
def format_timestamp(timestamp: int) -> str:
    """格式化时间戳"""
    return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")

def format_hash(hash_bytes) -> str:
    """格式化哈希值"""
    if hash_bytes is None:
        return "N/A"
    return hash_bytes.hex()[:32] + "..."

def get_server_status() -> Dict[str, Any]:
    """获取服务器状态"""
    latest_sth = log_server.get_latest_sth()
    status = {
        "tree_size": int(log_server.tree_size),
        "root_hash": format_hash(log_server.root_hash) if log_server.root_hash else "N/A",
        "public_key": format_hash(log_server.public_key),
        "latest_sth": {
            "tree_size": int(latest_sth.tree_size),
            "root_hash": format_hash(latest_sth.root_hash),
            "timestamp": format_timestamp(latest_sth.timestamp),
            "signature": format_hash(latest_sth.signature)
        } if latest_sth else {
            "tree_size": 0,
            "root_hash": "N/A",
            "timestamp": "N/A",
            "signature": "N/A"
        }
    }
    return status

# Web页面路由
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """主页"""
    status = get_server_status()
    template = jinja_env.get_template("index.html")
    content = template.render(request=request, status=status)
    return HTMLResponse(content=content)

@app.get("/submit", response_class=HTMLResponse)
async def submit_page(request: Request):
    """提交日志页面"""
    template = jinja_env.get_template("submit.html")
    content = template.render(request=request)
    return HTMLResponse(content=content)

@app.get("/query", response_class=HTMLResponse)
async def query_page(request: Request):
    """查询日志页面"""
    status = get_server_status()
    template = jinja_env.get_template("query.html")
    content = template.render(request=request, tree_size=status["tree_size"])
    return HTMLResponse(content=content)

@app.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request):
    """审计页面"""
    status = get_server_status()
    template = jinja_env.get_template("audit.html")
    content = template.render(request=request, status=status)
    return HTMLResponse(content=content)

@app.get("/verify", response_class=HTMLResponse)
async def verify_page(request: Request):
    """验证页面"""
    status = get_server_status()
    template = jinja_env.get_template("verify.html")
    content = template.render(request=request, tree_size=status["tree_size"])
    return HTMLResponse(content=content)

# API路由
@app.post("/api/submit")
async def submit_log(entry: LogEntry):
    """提交日志条目"""
    try:
        index = log_server.submit_log(entry.data.encode(), entry.timestamp)
        return {"success": True, "index": index, "message": "日志提交成功"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/submit/batch")
async def submit_batch(entries: List[LogEntry]):
    """批量提交日志"""
    try:
        indices = []
        for entry in entries:
            index = log_server.submit_log(entry.data.encode(), entry.timestamp)
            indices.append(index)
        return {"success": True, "indices": indices, "count": len(indices)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/log/{index}")
async def get_log(index: int):
    """获取日志条目"""
    try:
        data = log_server.get_log_entry(index)
        if data is None:
            raise HTTPException(status_code=404, detail="日志不存在")
        return {"success": True, "index": index, "data": data.decode('utf-8', errors='replace')}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/proof/inclusion/{index}")
async def get_inclusion_proof(index: int):
    """获取包含证明"""
    try:
        proof = log_server.get_inclusion_proof(index)
        return {
            "success": True,
            "leaf_index": proof.leaf_index,
            "leaf_hash": proof.leaf_hash.hex(),
            "tree_size": proof.tree_size,
            "proof_hashes": [h.hex() for h in proof.proof_hashes]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/proof/verify/inclusion")
async def verify_inclusion(request: VerifyRequest):
    """验证包含证明"""
    try:
        index = request.index
        log_data = log_server.get_log_entry(index)
        if log_data is None:
            return {"success": False, "message": "日志不存在"}
        
        proof = log_server.get_inclusion_proof(index)
        latest_sth = log_server.get_latest_sth()
        
        if latest_sth is None:
            return {"success": False, "message": "无可用的STH"}
        
        is_valid = MerkleTree.verify_inclusion_proof_with_data(log_data, proof, latest_sth.root_hash)
        
        return {
            "success": True,
            "index": index,
            "is_valid": is_valid,
            "message": "验证通过" if is_valid else "验证失败"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/proof/consistency")
async def get_consistency_proof(request: ConsistencyRequest):
    """获取一致性证明"""
    try:
        old_size = request.old_size
        proof = log_server.get_consistency_proof(old_size)
        latest_sth = log_server.get_latest_sth()
        
        if latest_sth is None:
            return {"success": False, "message": "无可用的STH"}
        
        is_valid = MerkleTree.verify_consistency_proof(
            proof, latest_sth.root_hash, log_server._storage.merkle_tree.leaves
        )
        
        return {
            "success": True,
            "old_size": proof.old_tree_size,
            "new_size": proof.new_tree_size,
            "old_root": proof.old_root_hash.hex(),
            "proof_hashes_count": len(proof.proof_hashes),
            "is_valid": is_valid,
            "message": "一致性验证通过" if is_valid else "一致性验证失败"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sth/latest")
async def get_latest_sth():
    """获取最新STH"""
    try:
        sth = log_server.get_latest_sth()
        if sth is None:
            return {"success": False, "message": "无可用的STH"}
        
        sig_valid = auditor.verify_sth_signature(sth)
        
        return {
            "success": True,
            "tree_size": sth.tree_size,
            "root_hash": sth.root_hash.hex(),
            "timestamp": format_timestamp(sth.timestamp),
            "signature": sth.signature.hex(),
            "signature_valid": sig_valid.result.value == "pass"
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/sth/all")
async def get_all_sth():
    """获取所有STH记录"""
    try:
        sths = log_server.get_all_sth_records()
        result = []
        for sth in sths:
            sig_valid = auditor.verify_sth_signature(sth)
            result.append({
                "tree_size": sth.tree_size,
                "root_hash": sth.root_hash.hex()[:32] + "...",
                "timestamp": format_timestamp(sth.timestamp),
                "signature_valid": sig_valid.result.value == "pass"
            })
        return {"success": True, "sths": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/audit/full")
async def full_audit():
    """执行完整审计"""
    try:
        latest_sth = log_server.get_latest_sth()
        if latest_sth is None:
            return {"success": False, "message": "无可用的STH"}
        
        report = auditor.full_audit(latest_sth)
        
        # 获取详细结果
        details = []
        for result in report.results:
            status = "PASS" if result.is_pass() else "FAIL" if result.is_fail() else "ERROR"
            details.append({
                "status": status,
                "message": result.message
            })
        
        return {
            "success": True,
            "verified_items": report.verified_items,
            "passed_items": report.passed_items,
            "failed_items": report.failed_items,
            "duration_ms": report.duration_ms,
            "message": "审计完成",
            "details": details
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/status")
async def get_status():
    """获取服务器状态"""
    return {"success": True, "data": get_server_status()}

@app.post("/api/sth/publish")
async def publish_sth():
    """强制发布STH"""
    try:
        sth = log_server.force_publish_sth()
        return {
            "success": True,
            "tree_size": sth.tree_size,
            "root_hash": sth.root_hash.hex()[:32] + "...",
            "timestamp": format_timestamp(sth.timestamp),
            "message": "STH发布成功"
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/log/count")
async def get_log_count():
    """获取日志数量"""
    return {"success": True, "count": log_server.tree_size}

# 启动时初始化
@app.on_event("startup")
async def startup_event():
    """启动时初始化"""
    print("防篡改审计日志系统 Web 服务启动")

@app.on_event("shutdown")
async def shutdown_event():
    """关闭时清理"""
    log_server.close()
    auditor.close()
    print("防篡改审计日志系统 Web 服务关闭")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)