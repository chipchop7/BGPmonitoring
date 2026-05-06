import asyncio
import datetime
import json
import os
import uuid

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from bgp.collector import fetch_bgp_summary, fetch_bgp_routes, fetch_peer_routes, fetch_peer_detail

app = FastAPI(title="BGP Monitor")

ROUTERS_FILE = "routers.json"

routers: dict[str, dict] = {}
bgp_status: dict[str, dict] = {}
alerts: list[dict] = []


# ── 永続化 ────────────────────────────────────────────────
def load_routers():
    if os.path.exists(ROUTERS_FILE):
        with open(ROUTERS_FILE) as f:
            return json.load(f)
    return {}

def save_routers():
    with open(ROUTERS_FILE, "w") as f:
        json.dump(routers, f, indent=2)


# ── ポーリング ─────────────────────────────────────────────
def poll_router(router_id: str, config: dict):
    old_peers = {p["neighbor"]: p["state"]
                 for p in bgp_status.get(router_id, {}).get("peers", [])}

    try:
        result = fetch_bgp_summary(config)
    except Exception as e:
        bgp_status[router_id] = {
            "error": str(e),
            "peers": bgp_status.get(router_id, {}).get("peers", []),
            "last_updated": datetime.datetime.now().isoformat(),
        }
        return

    result["last_updated"] = datetime.datetime.now().isoformat()
    result["error"] = None
    bgp_status[router_id] = result

    # 状態変化を検出してアラート生成
    for peer in result.get("peers", []):
        neighbor  = peer["neighbor"]
        new_state = peer["state"]
        old_state = old_peers.get(neighbor)
        if old_state and old_state != new_state:
            level = "info" if new_state == "Established" else "warning"
            alerts.insert(0, {
                "time":      datetime.datetime.now().isoformat(),
                "router":    config["name"],
                "neighbor":  neighbor,
                "remote_as": peer["remote_as"],
                "old_state": old_state,
                "new_state": new_state,
                "level":     level,
            })
    # アラートは最新100件だけ保持
    del alerts[100:]


async def poll_loop():
    while True:
        for router_id, config in list(routers.items()):
            try:
                await asyncio.to_thread(poll_router, router_id, config)
            except Exception:
                pass
        await asyncio.sleep(30)


@app.on_event("startup")
async def startup():
    global routers
    routers = load_routers()
    asyncio.create_task(poll_loop())


# ── API ───────────────────────────────────────────────────
class RouterIn(BaseModel):
    name:        str
    host:        str
    port:        int = 22
    username:    str = ""
    password:    str = ""
    ssh_key_path: str = ""          # 秘密鍵ファイルのパス（公開鍵認証用）
    device_type: str = "cisco_ios"  # cisco_ios | cisco_xr | juniper_junos | linux | demo


@app.get("/api/routers")
def list_routers():
    return [
        {"id": rid, "name": v["name"], "host": v["host"], "device_type": v["device_type"]}
        for rid, v in routers.items()
    ]


@app.post("/api/routers")
def add_router(body: RouterIn):
    rid = str(uuid.uuid4())[:8]
    routers[rid] = body.model_dump()
    save_routers()
    # 追加直後に即ポーリング
    asyncio.get_event_loop().run_in_executor(None, poll_router, rid, routers[rid])
    return {"id": rid}


@app.put("/api/routers/{rid}")
def update_router(rid: str, body: RouterIn):
    if rid not in routers:
        raise HTTPException(404, "Router not found")
    routers[rid] = body.model_dump()
    save_routers()
    asyncio.get_event_loop().run_in_executor(None, poll_router, rid, routers[rid])
    return {"ok": True}


@app.get("/api/routers/{rid}")
def get_router(rid: str):
    if rid not in routers:
        raise HTTPException(404, "Router not found")
    r = routers[rid]
    return {"id": rid, "name": r["name"], "host": r["host"],
            "port": r["port"], "username": r["username"],
            "password": r.get("password", ""),
            "ssh_key_path": r.get("ssh_key_path", ""),
            "device_type": r["device_type"]}


@app.delete("/api/routers/{rid}")
def remove_router(rid: str):
    if rid not in routers:
        raise HTTPException(404, "Router not found")
    del routers[rid]
    bgp_status.pop(rid, None)
    save_routers()
    return {"ok": True}


@app.get("/api/status")
def get_status():
    result = []
    for rid, cfg in routers.items():
        st = bgp_status.get(rid, {})
        result.append({
            "id":           rid,
            "name":         cfg["name"],
            "host":         cfg["host"],
            "device_type":  cfg["device_type"],
            "local_as":     st.get("local_as"),
            "router_id":    st.get("router_id"),
            "peers":        st.get("peers", []),
            "total_prefixes": st.get("total_prefixes", 0),
            "last_updated": st.get("last_updated"),
            "error":        st.get("error"),
        })
    return result


@app.post("/api/routers/{rid}/refresh")
async def refresh_router(rid: str):
    if rid not in routers:
        raise HTTPException(404, "Router not found")
    await asyncio.to_thread(poll_router, rid, routers[rid])
    return {"ok": True}


@app.get("/api/routers/{rid}/peers/{neighbor}/routes")
async def get_peer_routes(rid: str, neighbor: str, type: str = "advertised"):
    if rid not in routers:
        raise HTTPException(404, "Router not found")
    if type not in ("advertised", "received"):
        raise HTTPException(400, "type must be 'advertised' or 'received'")
    try:
        routes = await asyncio.to_thread(fetch_peer_routes, routers[rid], neighbor, type)
        return routes
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/routers/{rid}/peers/{neighbor}/detail")
async def get_peer_detail(rid: str, neighbor: str):
    if rid not in routers:
        raise HTTPException(404, "Router not found")
    try:
        detail = await asyncio.to_thread(fetch_peer_detail, routers[rid], neighbor)
        return detail
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/routers/{rid}/routes")
async def get_routes(rid: str):
    if rid not in routers:
        raise HTTPException(404, "Router not found")
    try:
        routes = await asyncio.to_thread(fetch_bgp_routes, routers[rid])
        return routes
    except Exception as e:
        raise HTTPException(500, str(e))


@app.get("/api/alerts")
def get_alerts():
    return alerts


# ── 静的ファイル & トップページ ───────────────────────────
app.mount("/static", StaticFiles(directory="static"), name="static")

@app.get("/")
def index():
    return FileResponse("static/index.html")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
