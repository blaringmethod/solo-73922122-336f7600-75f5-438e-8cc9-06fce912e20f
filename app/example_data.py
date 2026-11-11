"""内置“重叠规则”示例：新旧规则集均含互相重叠的 CIDR 与端口区间。

场景（均为首条匹配、默认拒绝语义）：
  * 旧 102 是排在宽放行 101 之前的窄 deny，在放行区里真实“挖洞”；新规则集
    把该洞改为窄 allow（202 仍在最前），对应流量由阻断变放行；
  * 新 205 对宽区域内的端口 1024 单独 deny（排在宽规则 201 前），新增一块阻断；
  * 新 203 把旧 103 对 192.168.1.0/24:443 的放行改为阻断；
  * 旧 104 的放行在新规则集中被整体删除，相关流量退回默认拒绝。
"""

EXAMPLE_OLD = [
    {
        "id": 102,
        "source": "10.1.0.0/16",
        "destination": "172.16.5.0/24",
        "portRange": [80, 80],
        "action": "deny",
    },
    {
        "id": 101,
        "source": "10.0.0.0/8",
        "destination": "172.16.0.0/12",
        "portRange": [1, 1024],
        "action": "allow",
    },
    {
        "id": 103,
        "source": "192.168.1.0/24",
        "destination": "0.0.0.0/0",
        "portRange": [443, 443],
        "action": "allow",
    },
    {
        "id": 104,
        "source": "10.0.0.0/8",
        "destination": "192.168.1.0/24",
        "portRange": [443, 443],
        "action": "allow",
    },
]

EXAMPLE_NEW = [
    {
        "id": 202,
        "source": "10.1.0.0/16",
        "destination": "172.16.5.0/24",
        "portRange": [80, 80],
        "action": "allow",
    },
    {
        "id": 205,
        "source": "10.0.0.0/8",
        "destination": "172.16.0.0/12",
        "portRange": [1024, 1024],
        "action": "deny",
    },
    {
        "id": 201,
        "source": "10.0.0.0/8",
        "destination": "172.16.0.0/12",
        "portRange": [1, 1024],
        "action": "allow",
    },
    {
        "id": 203,
        "source": "192.168.1.0/24",
        "destination": "0.0.0.0/0",
        "portRange": [443, 443],
        "action": "deny",
    },
]

EXAMPLE_PAYLOAD = {"old": EXAMPLE_OLD, "new": EXAMPLE_NEW}

# --------------------------------------------------------------------------- #
# 规则有效性审计示例：一份规则集内同时演示四种典型情形
#   * id=2：被 id=1 的宽 deny 完全遮蔽且动作冲突（allow 永不生效）；
#   * id=3：被 id=1 完全遮蔽但动作一致（冗余，删除不影响任何判定）；
#   * id=4：不与任何前置规则重叠，完全生效；
#   * id=5：端口 1-1024 段被 id=1 遮蔽（冲突），1025-2048 段真正生效（部分生效）。
# --------------------------------------------------------------------------- #
EXAMPLE_AUDIT = [
    {
        "id": 1,
        "source": "10.0.0.0/8",
        "destination": "172.16.0.0/12",
        "portRange": [1, 1024],
        "action": "deny",
    },
    {
        "id": 2,
        "source": "10.1.0.0/16",
        "destination": "172.16.5.0/24",
        "portRange": [80, 80],
        "action": "allow",
    },
    {
        "id": 3,
        "source": "10.2.0.0/16",
        "destination": "172.16.9.0/24",
        "portRange": [443, 443],
        "action": "deny",
    },
    {
        "id": 4,
        "source": "10.0.0.0/8",
        "destination": "172.16.0.0/12",
        "portRange": [8080, 8080],
        "action": "allow",
    },
    {
        "id": 5,
        "source": "10.3.0.0/16",
        "destination": "172.16.0.0/12",
        "portRange": [1, 2048],
        "action": "allow",
    },
]

AUDIT_EXAMPLE_PAYLOAD = {"rules": EXAMPLE_AUDIT}
