"""Tests for Streamlit app helper functions."""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from port_scanner.models import Protocol
from streamlit_app import (
    MAX_HOSTS_CIDR,
    MAX_PORTS_WEB,
    PRESETS,
    SCAN_COOLDOWN_SEC,
    _build_ports,
    _check_cooldown,
    _expand_targets,
    _is_safe_target,
)


class TestBuildPorts:
    """Tests for _build_ports helper."""

    def test_single_port(self) -> None:
        ports = _build_ports("80", "Custom", Protocol.TCP)
        assert len(ports) == 1
        assert ports[0].number == 80
        assert ports[0].protocol == Protocol.TCP

    def test_multiple_ports(self) -> None:
        ports = _build_ports("80,443,8080", "Custom", Protocol.TCP)
        assert len(ports) == 3
        assert [p.number for p in ports] == [80, 443, 8080]

    def test_port_range(self) -> None:
        ports = _build_ports("80-83", "Custom", Protocol.TCP)
        assert len(ports) == 4
        assert [p.number for p in ports] == [80, 81, 82, 83]

    def test_mixed_ports_and_ranges(self) -> None:
        ports = _build_ports("22,80-82,443", "Custom", Protocol.TCP)
        assert len(ports) == 5
        assert [p.number for p in ports] == [22, 80, 81, 82, 443]

    def test_deduplication(self) -> None:
        ports = _build_ports("80,80,80", "Custom", Protocol.TCP)
        assert len(ports) == 1

    def test_empty_custom_returns_empty(self) -> None:
        ports = _build_ports("", "Custom", Protocol.TCP)
        assert ports == []

    def test_preset_overrides_custom_spec(self) -> None:
        ports = _build_ports("9999", "Quick (Top 20)", Protocol.TCP)
        assert len(ports) == 20
        assert 80 in [p.number for p in ports]

    def test_ports_capped_at_max(self) -> None:
        big_range = ",".join(str(i) for i in range(1, 2000))
        ports = _build_ports(big_range, "Custom", Protocol.TCP)
        assert len(ports) <= MAX_PORTS_WEB

    def test_all_presets_parse(self) -> None:
        for name, spec in PRESETS.items():
            if name == "Custom" or not spec:
                continue
            ports = _build_ports(spec, name, Protocol.TCP)
            assert len(ports) > 0, f"Preset '{name}' produced no ports"
            for p in ports:
                assert 1 <= p.number <= 65535

    def test_udp_protocol(self) -> None:
        ports = _build_ports("53,67,123", "Custom", Protocol.UDP)
        assert all(p.protocol == Protocol.UDP for p in ports)
        assert [p.number for p in ports] == [53, 67, 123]


class TestIsSafeTarget:
    """Tests for _is_safe_target helper."""

    def test_localhost(self) -> None:
        assert _is_safe_target("localhost") is True

    def test_loopback_ip(self) -> None:
        assert _is_safe_target("127.0.0.1") is True

    def test_ipv6_loopback(self) -> None:
        assert _is_safe_target("::1") is True

    def test_resolvable_hostname(self) -> None:
        assert _is_safe_target("google.com") is True

    def test_unresolvable_hostname(self) -> None:
        assert _is_safe_target("this-host-does-not-exist-xyz.invalid") is False

    def test_empty_string(self) -> None:
        assert _is_safe_target("") is False

    def test_cidr_notation(self) -> None:
        assert _is_safe_target("192.168.1.0/24") is True

    def test_invalid_cidr(self) -> None:
        assert _is_safe_target("999.999.999.999/24") is False

    def test_scanme_nmap_org(self) -> None:
        """Nmap's official test target should resolve."""
        assert _is_safe_target("scanme.nmap.org") is True


class TestExpandTargets:
    """Tests for _expand_targets helper."""

    def test_single_host(self) -> None:
        targets = _expand_targets("example.com")
        assert targets == ["example.com"]

    def test_cidr_slash_30(self) -> None:
        targets = _expand_targets("192.168.1.0/30")
        assert len(targets) == 2
        assert "192.168.1.1" in targets
        assert "192.168.1.2" in targets

    def test_comma_separated(self) -> None:
        targets = _expand_targets("host1.com,host2.com")
        assert targets == ["host1.com", "host2.com"]

    def test_cidr_capped(self) -> None:
        targets = _expand_targets("10.0.0.0/16")  # 65534 hosts
        assert len(targets) <= MAX_HOSTS_CIDR

    def test_mixed_cidr_and_hostname(self) -> None:
        targets = _expand_targets("example.com,192.168.1.0/30")
        assert "example.com" in targets
        assert len(targets) == 3

    def test_empty_string(self) -> None:
        targets = _expand_targets("")
        assert targets == []


class TestCooldown:
    """Tests for _check_cooldown helper."""

    def test_no_previous_scan(self) -> None:
        import streamlit_app

        keys_to_remove = [k for k in streamlit_app.st.session_state if k == "last_scan_time"]
        for k in keys_to_remove:
            del streamlit_app.st.session_state[k]
        assert _check_cooldown() is True

    def test_cooldown_active(self) -> None:
        import streamlit_app

        streamlit_app.st.session_state["last_scan_time"] = time.time()
        assert _check_cooldown() is False

    def test_cooldown_expired(self) -> None:
        import streamlit_app

        streamlit_app.st.session_state["last_scan_time"] = time.time() - SCAN_COOLDOWN_SEC - 1
        assert _check_cooldown() is True
