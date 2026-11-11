"""FastAPI 接口测试。"""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

GOOD_OLD = '''[
  {"id": 1, "source": "10.0.0.0/8", "destination": "172.16.0.0/12",
   "portRange": [80, 80], "action": "allow"}
]'''
GOOD_NEW = '''[
  {"id": 1, "source": "10.0.0.0/8", "destination": "172.16.0.0/12",
   "portRange": [80, 80], "action": "deny"}
]'''


def test_health():
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_index_page_served():
    resp = client.get("/")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "防火墙规则变更差分台" in resp.text


def test_analyze_happy_path():
    resp = client.post("/api/analyze", json={"old": GOOD_OLD, "new": GOOD_NEW})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    result = data["result"]
    # allow -> deny：唯一一块新增阻断
    assert result["summary"]["newlyDeniedBlockCount"] == 1
    assert result["summary"]["newlyAllowedBlockCount"] == 0
    blk = result["newlyDenied"][0]
    assert blk["source"]["cidr"] == "10.0.0.0/8"
    assert blk["destination"]["cidr"] == "172.16.0.0/12"
    assert blk["port"]["start"] == 80
    assert blk["oldVerdict"]["action"] == "allow"
    assert blk["newVerdict"]["action"] == "deny"
    assert blk["representativePacket"]["protocol"] == "TCP"


def test_analyze_validation_error_400_with_location():
    bad = '[{"id": 1, "source": "10.0.0.5/24", "destination": "0.0.0.0/0",' \
          ' "portRange": [80], "action": "maybe"}]'
    resp = client.post("/api/analyze", json={"old": GOOD_OLD, "new": bad})
    assert resp.status_code == 400
    data = resp.json()
    assert data["ok"] is False
    fields = {e.get("field") for e in data["errors"]}
    assert {"source", "portRange", "action"} <= fields
    assert all(e["sheet"] == "new" for e in data["errors"])


def test_analyze_json_syntax_error_location():
    resp = client.post("/api/analyze",
                       json={"old": "not json at all", "new": GOOD_NEW})
    assert resp.status_code == 400
    err = resp.json()["errors"][0]
    assert err["sheet"] == "old" and "JSON" in err["message"]


def test_example_endpoint_loadable_and_diff_runs():
    resp = client.get("/api/example")
    assert resp.status_code == 200
    payload = resp.json()
    assert isinstance(payload["old"], list) and isinstance(payload["new"], list)
    # 示例自身必须通过校验并产生结果
    import json
    resp2 = client.post("/api/analyze", json={
        "old": json.dumps(payload["old"]),
        "new": json.dumps(payload["new"]),
    })
    assert resp2.status_code == 200
    body = resp2.json()
    assert body["ok"] is True
    assert body["result"]["summary"]["totalChangedBlockCount"] >= 1


def test_missing_body_field_422():
    resp = client.post("/api/analyze", json={"old": GOOD_OLD})
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# 规则有效性审计
# --------------------------------------------------------------------------- #
AUDIT_RULES = '''[
  {"id": 1, "source": "10.0.0.0/8", "destination": "172.16.0.0/12",
   "portRange": [1, 1024], "action": "deny"},
  {"id": 2, "source": "10.1.0.0/16", "destination": "172.16.5.0/24",
   "portRange": [80, 80], "action": "allow"}
]'''


def test_audit_page_served():
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "规则有效性审计" in resp.text


def test_index_page_links_to_audit():
    resp = client.get("/")
    assert resp.status_code == 200
    assert 'href="/audit"' in resp.text


def test_audit_page_links_back_to_diff():
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert 'href="/"' in resp.text


def test_audit_happy_path():
    resp = client.post("/api/audit", json={"rules": AUDIT_RULES})
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    result = data["result"]
    assert result["summary"]["ruleCount"] == 2
    assert result["summary"]["fullyShadowedCount"] == 1
    assert result["summary"]["conflictRuleCount"] == 1
    r2 = result["rules"][1]
    assert r2["status"] == "fully-shadowed"
    assert r2["actionConflict"] is True
    assert r2["shadowedBy"][0]["ruleId"] == 1
    pkt = r2["shadowedBlocks"][0]["representativePacket"]
    assert pkt["protocol"] == "TCP"
    assert pkt["destinationPort"] == 80


def test_audit_validation_error_400_with_location():
    bad = '[{"id": 1, "source": "10.0.0.5/24", "destination": "0.0.0.0/0",' \
          ' "portRange": [80], "action": "maybe"}]'
    resp = client.post("/api/audit", json={"rules": bad})
    assert resp.status_code == 400
    data = resp.json()
    assert data["ok"] is False
    fields = {e.get("field") for e in data["errors"]}
    assert {"source", "portRange", "action"} <= fields
    assert all(e["sheet"] == "rules" for e in data["errors"])


def test_audit_json_syntax_error_location():
    resp = client.post("/api/audit", json={"rules": "not json at all"})
    assert resp.status_code == 400
    err = resp.json()["errors"][0]
    assert err["sheet"] == "rules" and "JSON" in err["message"]


def test_audit_example_loadable_and_runs():
    resp = client.get("/api/audit/example")
    assert resp.status_code == 200
    payload = resp.json()
    assert isinstance(payload["rules"], list) and payload["rules"]
    import json
    resp2 = client.post("/api/audit", json={"rules": json.dumps(payload["rules"])})
    assert resp2.status_code == 200
    body = resp2.json()
    assert body["ok"] is True
    s = body["result"]["summary"]
    # 示例应同时演示完全遮蔽、部分生效、完全生效与动作冲突
    assert s["fullyShadowedCount"] >= 1
    assert s["partiallyEffectiveCount"] >= 1
    assert s["fullyEffectiveCount"] >= 1
    assert s["conflictRuleCount"] >= 1
    assert s["redundantRuleCount"] >= 1


def test_audit_missing_body_field_422():
    resp = client.post("/api/audit", json={})
    assert resp.status_code == 422
