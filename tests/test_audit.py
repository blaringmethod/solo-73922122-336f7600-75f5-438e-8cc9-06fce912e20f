"""规则有效性审计引擎测试：生效区域精确性、遮蔽来源、动作冲突与建议。"""

import json
import random
from ipaddress import IPv4Address, IPv4Network

import pytest

from app.engine import (
    Rule,
    ValidationFailure,
    analyze_audit,
    audit_ruleset,
    parse_ruleset,
)


# --------------------------------------------------------------------------- #
# 工具
# --------------------------------------------------------------------------- #
def make_rule(rid, order, src, dst, plo, phi, action):
    return Rule(id=rid, order=order, source=IPv4Network(src),
                destination=IPv4Network(dst), port_low=plo, port_high=phi,
                action=action)


def ref_hit(rules, sip_int, dip_int, port):
    """参考实现：顺序扫描，首条命中；未命中返回 -1。"""
    for r in rules:
        if (int(r.source.network_address) <= sip_int
                <= int(r.source.broadcast_address)
                and int(r.destination.network_address) <= dip_int
                <= int(r.destination.broadcast_address)
                and r.port_low <= port <= r.port_high):
            return r.order
    return -1


def ip_int(s):
    return int(IPv4Address(s))


def block_ranges(blocks):
    return [(
        ip_int(b["source"]["start"]), ip_int(b["source"]["end"]),
        ip_int(b["destination"]["start"]), ip_int(b["destination"]["end"]),
        b["port"]["start"], b["port"]["end"],
    ) for b in blocks]


def overlap1d(a_lo, a_hi, b_lo, b_hi):
    return a_lo <= b_hi and b_lo <= a_hi


def boxes_overlap(a, b):
    return (overlap1d(a[0], a[1], b[0], b[1])
            and overlap1d(a[2], a[3], b[2], b[3])
            and overlap1d(a[4], a[5], b[4], b[5]))


def assert_pairwise_disjoint(ranges):
    for i in range(len(ranges)):
        for j in range(i + 1, len(ranges)):
            assert not boxes_overlap(ranges[i], ranges[j]), (ranges[i], ranges[j])


def build_point_map(entries, sip0, dip0, port0, n_ports, dst_stride):
    """把若干 (范围, 标签) 展开为点→标签映射；重叠即断言失败。"""
    point_map: dict[int, object] = {}
    for ranges, tag in entries:
        for slo, shi, dlo, dhi, plo, phi in ranges:
            for sip in range(slo, shi + 1):
                s_part = (sip - sip0) * dst_stride
                for dip in range(dlo, dhi + 1):
                    sd_part = (s_part + (dip - dip0)) * n_ports
                    for port in range(plo, phi + 1):
                        key = sd_part + (port - port0)
                        assert key not in point_map, "输出块在该点重叠"
                        point_map[key] = tag
    return point_map


# --------------------------------------------------------------------------- #
# 分类：完全遮蔽（冲突 / 冗余）、部分生效、完全生效
# --------------------------------------------------------------------------- #
def test_fully_shadowed_with_action_conflict():
    rules = [
        make_rule(1, 0, "10.0.0.0/8", "172.16.0.0/12", 1, 1024, "deny"),
        make_rule(2, 1, "10.1.0.0/16", "172.16.5.0/24", 80, 80, "allow"),
    ]
    result = audit_ruleset(rules)
    r1, r2 = result["rules"]

    assert r1["status"] == "fully-effective"
    assert r1["actionConflict"] is False
    assert r1["shadowedBlocks"] == []

    assert r2["status"] == "fully-shadowed"
    assert r2["actionConflict"] is True
    assert r2["effectiveBlocks"] == []
    assert r2["effectivePacketCount"] == "0"
    assert r2["shadowedPacketCount"] == r2["declaredPacketCount"]
    assert r2["effectivePercent"] == "0.00"
    assert r2["shadowedPercent"] == "100.00"

    # 遮蔽来源唯一且为规则 1，动作冲突
    assert len(r2["shadowedBy"]) == 1
    sh = r2["shadowedBy"][0]
    assert sh["ruleId"] == 1 and sh["ruleOrder"] == 1
    assert sh["relation"] == "conflict"
    assert sh["packetCount"] == r2["declaredPacketCount"]

    # 被遮蔽区域恰好等于声明区域
    assert len(r2["shadowedBlocks"]) == 1
    blk = r2["shadowedBlocks"][0]
    assert blk["source"]["cidr"] == "10.1.0.0/16"
    assert blk["destination"]["cidr"] == "172.16.5.0/24"
    assert blk["port"]["start"] == blk["port"]["end"] == 80
    assert blk["shadowedBy"]["ruleId"] == 1
    assert blk["relation"] == "conflict"
    # 代表报文实际命中规则 1（deny），不是规则 2
    pkt = blk["representativePacket"]
    assert ref_hit(rules, ip_int(pkt["sourceIp"]), ip_int(pkt["destinationIp"]),
                   pkt["destinationPort"]) == 0
    # 汇总统计
    s = result["summary"]
    assert s["ruleCount"] == 2
    assert s["fullyShadowedCount"] == 1
    assert s["conflictRuleCount"] == 1
    assert s["redundantRuleCount"] == 0


def test_fully_shadowed_same_action_is_redundant():
    rules = [
        make_rule("broad", 0, "10.0.0.0/8", "0.0.0.0/0", 1, 65535, "deny"),
        make_rule("narrow", 1, "10.9.0.0/16", "192.168.0.0/24", 22, 22, "deny"),
    ]
    result = audit_ruleset(rules)
    r2 = result["rules"][1]
    assert r2["status"] == "fully-shadowed"
    assert r2["actionConflict"] is False
    assert r2["shadowedBy"][0]["relation"] == "same-action"
    assert "冗余" in r2["suggestion"]
    assert result["summary"]["redundantRuleCount"] == 1
    assert result["summary"]["conflictRuleCount"] == 0


def test_partially_effective_exact_regions():
    rules = [
        make_rule(1, 0, "10.0.0.0/8", "172.16.0.0/12", 1, 1024, "deny"),
        make_rule(5, 1, "10.3.0.0/16", "172.16.0.0/12", 1, 2048, "allow"),
    ]
    result = audit_ruleset(rules)
    r = result["rules"][1]
    assert r["status"] == "partially-effective"
    assert r["actionConflict"] is True

    # 生效区域：端口 1025-2048；被遮蔽区域：端口 1-1024（来源规则 1，冲突）
    assert len(r["effectiveBlocks"]) == 1
    eff = r["effectiveBlocks"][0]
    assert eff["source"]["cidr"] == "10.3.0.0/16"
    assert eff["destination"]["cidr"] == "172.16.0.0/12"
    assert (eff["port"]["start"], eff["port"]["end"]) == (1025, 2048)

    assert len(r["shadowedBlocks"]) == 1
    shd = r["shadowedBlocks"][0]
    assert (shd["port"]["start"], shd["port"]["end"]) == (1, 1024)
    assert shd["shadowedBy"]["ruleId"] == 1
    assert shd["relation"] == "conflict"

    # 计数守恒：生效 + 被遮蔽 = 声明
    declared = int(r["declaredPacketCount"])
    assert int(r["effectivePacketCount"]) + int(r["shadowedPacketCount"]) == declared
    unit = 65536 * (2 ** 20)  # /16 × /12
    assert declared == unit * 2048
    assert int(r["effectivePacketCount"]) == unit * 1024
    assert r["effectivePercent"] == "50.00"


def test_fully_effective_single_rule():
    rules = [make_rule(1, 0, "0.0.0.0/0", "0.0.0.0/0", 0, 65535, "allow")]
    result = audit_ruleset(rules)
    r = result["rules"][0]
    assert r["status"] == "fully-effective"
    assert r["effectivePacketCount"] == r["declaredPacketCount"]
    assert r["shadowedPacketCount"] == "0"
    assert r["effectivePercent"] == "100.00"
    assert len(r["effectiveBlocks"]) == 1
    blk = r["effectiveBlocks"][0]
    assert blk["source"]["cidr"] == "0.0.0.0/0"
    assert blk["destination"]["cidr"] == "0.0.0.0/0"
    assert (blk["port"]["start"], blk["port"]["end"]) == (0, 65535)
    assert result["summary"]["fullyEffectiveCount"] == 1


def test_empty_ruleset_audits_clean():
    result = analyze_audit("[]")
    assert result["summary"]["ruleCount"] == 0
    assert result["rules"] == []


def test_builtin_audit_example_categories():
    from app.example_data import EXAMPLE_AUDIT
    result = analyze_audit(json.dumps(EXAMPLE_AUDIT))
    by_id = {r["ruleId"]: r for r in result["rules"]}
    assert by_id[1]["status"] == "fully-effective"
    assert by_id[2]["status"] == "fully-shadowed" and by_id[2]["actionConflict"]
    assert by_id[3]["status"] == "fully-shadowed" and not by_id[3]["actionConflict"]
    assert by_id[4]["status"] == "fully-effective"
    assert by_id[5]["status"] == "partially-effective" and by_id[5]["actionConflict"]
    s = result["summary"]
    assert s["fullyShadowedCount"] == 2
    assert s["partiallyEffectiveCount"] == 1
    assert s["fullyEffectiveCount"] == 2
    assert s["conflictRuleCount"] == 2
    assert s["redundantRuleCount"] == 1


# --------------------------------------------------------------------------- #
# 输入校验：定位字段，sheet 为 rules
# --------------------------------------------------------------------------- #
def test_audit_invalid_input_locates_field():
    bad = '[{"id": 1, "source": "10.0.0.5/24", "destination": "0.0.0.0/0",' \
          ' "portRange": [80], "action": "maybe"}]'
    with pytest.raises(ValidationFailure) as ei:
        analyze_audit(bad)
    fields = {e.get("field") for e in ei.value.errors}
    assert {"source", "portRange", "action"} <= fields
    assert all(e["sheet"] == "rules" for e in ei.value.errors)


def test_audit_json_syntax_error_has_position():
    with pytest.raises(ValidationFailure) as ei:
        analyze_audit('[{"id": 1,}\n]')
    err = ei.value.errors[0]
    assert err["sheet"] == "rules"
    assert err["line"] == 1 and err["col"] is not None


def test_audit_empty_input_rejected():
    with pytest.raises(ValidationFailure):
        analyze_audit("   ")


# --------------------------------------------------------------------------- #
# 多遮蔽来源 + 区域性质：互不重叠、并集等于声明区域、代表报文命中正确
# --------------------------------------------------------------------------- #
def test_multiple_shadowers_and_tiling():
    """一条规则被两条前置规则分别遮蔽不同部分，剩余部分生效。"""
    rules = [
        make_rule(1, 0, "10.0.0.0/25", "192.168.0.0/25", 80, 80, "deny"),
        make_rule(2, 1, "10.0.0.128/25", "192.168.0.0/25", 80, 80, "deny"),
        make_rule(3, 2, "10.0.0.0/24", "192.168.0.0/24", 80, 80, "allow"),
    ]
    result = audit_ruleset(rules)
    r3 = result["rules"][2]
    assert r3["status"] == "partially-effective"
    # 两个遮蔽来源，均与本规则动作冲突
    assert [a["ruleId"] for a in r3["shadowedBy"]] == [1, 2]
    assert all(a["relation"] == "conflict" for a in r3["shadowedBy"])

    # 生效 ∪ 各遮蔽块：互不重叠且恰好铺满声明区域（逐点核对）
    sip0 = ip_int("10.0.0.0")
    dip0 = ip_int("192.168.0.0")
    entries = [(block_ranges(r3["effectiveBlocks"]), ("eff", None))]
    for blk in r3["shadowedBlocks"]:
        entries.append((block_ranges([blk]), ("shd", blk["shadowedBy"]["ruleOrder"])))
    point_map = build_point_map(entries, sip0, dip0, 80, 1, 256)

    assert len(point_map) == 256 * 256  # 恰好铺满 /24 × /24 × {80}
    for sip in range(sip0, sip0 + 256):
        for dip in range(dip0, dip0 + 256):
            key = ((sip - sip0) * 256 + (dip - dip0)) * 1 + 0
            hit = ref_hit(rules, sip, dip, 80)
            if hit == 2:
                assert point_map[key] == ("eff", None)
            else:
                assert point_map[key] == ("shd", hit + 1)


def test_representative_packets_hit_expected_rules():
    """每个输出块的代表报文，独立复算的首条命中必须与块标注一致。"""
    rules = [
        make_rule("a", 0, "172.16.0.0/12", "10.0.0.0/8", 1, 1024, "deny"),
        make_rule("b", 1, "172.16.5.0/24", "10.1.0.0/16", 443, 443, "allow"),
        make_rule("c", 2, "172.16.5.0/24", "10.1.0.0/16", 1, 65535, "allow"),
        make_rule("d", 3, "172.16.0.0/12", "10.2.0.0/16", 8080, 8080, "allow"),
    ]
    result = audit_ruleset(rules)
    for report in result["rules"]:
        for blk in report["effectiveBlocks"]:
            pkt = blk["representativePacket"]
            hit = ref_hit(rules, ip_int(pkt["sourceIp"]),
                          ip_int(pkt["destinationIp"]), pkt["destinationPort"])
            assert hit == report["ruleIndex"] - 1
        for blk in report["shadowedBlocks"]:
            pkt = blk["representativePacket"]
            hit = ref_hit(rules, ip_int(pkt["sourceIp"]),
                          ip_int(pkt["destinationIp"]), pkt["destinationPort"])
            assert hit == blk["shadowedBy"]["ruleOrder"] - 1
    # 块间互不重叠（全部规则的所有块分别检查）
    for report in result["rules"]:
        assert_pairwise_disjoint(
            block_ranges(report["effectiveBlocks"] + report["shadowedBlocks"]))


def test_counts_conservation_all_rules():
    """每条规则：生效 + 被遮蔽 = 声明；遮蔽来源计数之和 = 被遮蔽总数。"""
    from app.example_data import EXAMPLE_AUDIT
    result = analyze_audit(json.dumps(EXAMPLE_AUDIT))
    for r in result["rules"]:
        declared = int(r["declaredPacketCount"])
        eff = int(r["effectivePacketCount"])
        shd = int(r["shadowedPacketCount"])
        assert eff + shd == declared
        assert sum(int(a["packetCount"]) for a in r["shadowedBy"]) == shd
        assert sum(int(b["packetCount"]) for b in r["effectiveBlocks"]) == eff
        assert sum(int(b["packetCount"]) for b in r["shadowedBlocks"]) == shd


# --------------------------------------------------------------------------- #
# 随机性质测试：受限子空间内逐点枚举（非抽样）核对每条规则
# --------------------------------------------------------------------------- #
def test_randomized_audit_against_bruteforce():
    rng = random.Random(20261111)
    pool_s = ["10.0.0.0/28", "10.0.0.0/29", "10.0.0.8/29", "10.0.0.0/30"]
    pool_d = ["192.168.1.0/28", "192.168.1.0/29", "192.168.1.8/29"]
    port_lo, port_hi = 77, 98
    n_ports = port_hi - port_lo + 1
    sip0 = int(IPv4Address("10.0.0.0"))
    dip0 = int(IPv4Address("192.168.1.0"))

    def rand_rules(n):
        out = []
        for i in range(n):
            lo = rng.randint(80, 90)
            hi = rng.randint(lo, 95)
            out.append(make_rule(f"r{i}", i, rng.choice(pool_s),
                                 rng.choice(pool_d), lo, hi,
                                 rng.choice(["allow", "deny"])))
        return out

    for trial in range(20):
        rules = rand_rules(rng.randint(0, 6))
        result = audit_ruleset(rules)
        assert result["summary"]["ruleCount"] == len(rules)

        for report in result["rules"]:
            i = report["ruleIndex"] - 1
            rule = rules[i]
            # 声明区域必然落在枚举宇宙内（规则网络均取自池）
            rs_lo = int(rule.source.network_address)
            rs_hi = int(rule.source.broadcast_address)
            rd_lo = int(rule.destination.network_address)
            rd_hi = int(rule.destination.broadcast_address)

            entries = [(block_ranges(report["effectiveBlocks"]), ("eff", None))]
            for blk in report["shadowedBlocks"]:
                entries.append((block_ranges([blk]),
                                ("shd", blk["shadowedBy"]["ruleOrder"])))
            point_map = build_point_map(entries, sip0, dip0, port_lo,
                                        n_ports, 16)

            # 声明区域内逐点核对：归属与遮蔽来源必须精确一致
            expected = 0
            for sip in range(rs_lo, rs_hi + 1):
                for dip in range(rd_lo, rd_hi + 1):
                    for port in range(rule.port_low, rule.port_high + 1):
                        key = ((sip - sip0) * 16 + (dip - dip0)) * n_ports \
                            + (port - port_lo)
                        hit = ref_hit(rules, sip, dip, port)
                        if hit == i:
                            assert point_map.get(key) == ("eff", None), trial
                        else:
                            assert 0 <= hit < i
                            assert point_map.get(key) == ("shd", hit + 1), trial
                        expected += 1
            # 无遗漏、无多余；且与声明计数一致
            assert len(point_map) == expected
            assert int(report["declaredPacketCount"]) == expected
            assert (int(report["effectivePacketCount"])
                    + int(report["shadowedPacketCount"]) == expected)

            # 状态与计数自洽
            eff = int(report["effectivePacketCount"])
            if eff == 0:
                assert report["status"] == "fully-shadowed"
            elif eff == expected:
                assert report["status"] == "fully-effective"
            else:
                assert report["status"] == "partially-effective"
            # 动作冲突标记与遮蔽来源一致
            expect_conflict = any(
                a["relation"] == "conflict" for a in report["shadowedBy"])
            assert report["actionConflict"] == expect_conflict
