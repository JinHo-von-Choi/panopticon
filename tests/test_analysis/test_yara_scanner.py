"""Tests for YaraScanner.

작성자: 최진호
작성일: 2026-02-20
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path
from types import ModuleType
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers: build a fake ``yara`` module so tests run without yara-python
# ---------------------------------------------------------------------------

def _make_fake_yara() -> ModuleType:
    """Create a minimal fake ``yara`` module with compile() and Error."""
    mod = ModuleType("yara")
    mod.Error = type("Error", (Exception,), {})  # type: ignore[attr-defined]
    mod.compile = MagicMock(name="yara.compile")  # type: ignore[attr-defined]
    return mod


def _make_match(rule: str, tags: list[str] | None = None, meta: dict | None = None):
    """Create a fake YARA match object."""
    m = MagicMock()
    m.rule = rule
    m.tags = tags or []
    m.meta = meta or {}
    return m


def _build_scanner(tmp_path, fake_yara, *, create_rules: bool = False, **kwargs):
    """Build a YaraScanner inside a patched sys.modules context.

    Returns (scanner, patch_ctx) -- caller must keep patch_ctx alive
    (use as context manager) for subsequent method calls that do
    ``import yara`` internally.
    """
    if create_rules:
        (tmp_path / "test.yar").write_text("rule test { condition: true }")
        compiled = MagicMock(name="compiled_rules")
        fake_yara.compile.return_value = compiled

    ctx = patch.dict("sys.modules", {"yara": fake_yara})
    ctx.start()

    import netwatcher.analysis.yara_scanner as mod
    importlib.reload(mod)
    scanner = mod.YaraScanner(rules_dir=str(tmp_path), **kwargs)
    return scanner, ctx


# ---------------------------------------------------------------------------
# Test: availability detection
# ---------------------------------------------------------------------------

class TestYaraScannerAvailability:
    """is_available() reflects whether yara-python can be imported."""

    def test_available_when_yara_installed(self, tmp_path):
        """Should return True when yara-python is importable."""
        fake_yara = _make_fake_yara()
        fake_yara.compile.return_value = MagicMock()

        scanner, ctx = _build_scanner(tmp_path, fake_yara)
        try:
            assert scanner.is_available() is True
        finally:
            ctx.stop()

    def test_unavailable_when_yara_missing(self, tmp_path):
        """Should return False when import yara raises ImportError."""
        ctx = patch.dict("sys.modules", {"yara": None})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))
            assert scanner.is_available() is False
        finally:
            ctx.stop()


# ---------------------------------------------------------------------------
# Test: rule loading
# ---------------------------------------------------------------------------

class TestYaraScannerRuleLoading:
    """_load_rules() discovers .yar/.yara files and calls yara.compile."""

    def test_no_yar_files_yields_none(self, tmp_path):
        """When rules dir has no .yar files, _compiled should be None."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(tmp_path, fake_yara)
        try:
            assert scanner._compiled is None
            assert scanner.rules_count == 0
            fake_yara.compile.assert_not_called()
        finally:
            ctx.stop()

    def test_multiple_yar_files_compiled(self, tmp_path):
        """All .yar files should be passed to yara.compile(filepaths=...)."""
        (tmp_path / "rule_a.yar").write_text("rule a { condition: true }")
        (tmp_path / "rule_b.yar").write_text("rule b { condition: true }")
        (tmp_path / "readme.txt").write_text("not a rule")  # non-.yar ignored

        fake_yara = _make_fake_yara()
        compiled_rules = MagicMock(name="compiled_rules")
        fake_yara.compile.return_value = compiled_rules

        ctx = patch.dict("sys.modules", {"yara": fake_yara})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))

            fake_yara.compile.assert_called_once()
            call_kwargs = fake_yara.compile.call_args
            filepaths = call_kwargs[1]["filepaths"]
            assert "rule_a" in filepaths
            assert "rule_b" in filepaths
            assert len(filepaths) == 2
            # Verify includes=False is passed for security
            assert call_kwargs[1]["includes"] is False
            assert scanner._compiled is compiled_rules
            assert scanner.rules_count == 2
        finally:
            ctx.stop()

    def test_yara_extension_supported(self, tmp_path):
        """.yara extension files should also be loaded."""
        (tmp_path / "rule_a.yar").write_text("rule a { condition: true }")
        (tmp_path / "rule_b.yara").write_text("rule b { condition: true }")

        fake_yara = _make_fake_yara()
        compiled_rules = MagicMock(name="compiled_rules")
        fake_yara.compile.return_value = compiled_rules

        ctx = patch.dict("sys.modules", {"yara": fake_yara})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))

            call_kwargs = fake_yara.compile.call_args
            filepaths = call_kwargs[1]["filepaths"]
            assert "rule_a" in filepaths
            assert "rule_b" in filepaths
            assert len(filepaths) == 2
            assert scanner.rules_count == 2
        finally:
            ctx.stop()

    def test_nonexistent_rules_dir(self, tmp_path):
        """When rules dir doesn't exist, _compiled should be None."""
        fake_yara = _make_fake_yara()

        ctx = patch.dict("sys.modules", {"yara": fake_yara})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path / "nonexistent"))
            assert scanner._compiled is None
            assert scanner.rules_count == 0
        finally:
            ctx.stop()

    def test_compile_error_handled(self, tmp_path):
        """When yara.compile raises yara.Error, _compiled should be None."""
        (tmp_path / "bad.yar").write_text("invalid rule")

        fake_yara = _make_fake_yara()
        fake_yara.compile.side_effect = fake_yara.Error("syntax error")

        ctx = patch.dict("sys.modules", {"yara": fake_yara})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))
            assert scanner._compiled is None
            assert scanner.rules_count == 0
        finally:
            ctx.stop()


# ---------------------------------------------------------------------------
# Test: scan_file and scan_bytes
# ---------------------------------------------------------------------------

class TestYaraScannerScan:
    """scan_file() and scan_bytes() return structured match dicts."""

    def test_scan_file_unavailable_returns_empty(self, tmp_path):
        """When yara not available, scan_file returns []."""
        ctx = patch.dict("sys.modules", {"yara": None})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))
            assert scanner.scan_file(str(tmp_path / "anything.bin")) == []
        finally:
            ctx.stop()

    def test_scan_file_no_rules_returns_empty(self, tmp_path):
        """When no rules compiled, scan_file returns []."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(tmp_path, fake_yara, create_rules=False)
        try:
            assert scanner.scan_file(str(tmp_path / "anything.bin")) == []
        finally:
            ctx.stop()

    def test_scan_file_not_found(self, tmp_path):
        """When file doesn't exist, scan_file returns []."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(tmp_path, fake_yara, create_rules=True)
        try:
            result = scanner.scan_file(str(tmp_path / "ghost.bin"))
            assert result == []
        finally:
            ctx.stop()

    def test_scan_file_with_matches(self, tmp_path):
        """scan_file returns dicts with rule/tags/meta from matches."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(tmp_path, fake_yara, create_rules=True)
        try:
            target = tmp_path / "payload.bin"
            target.write_bytes(b"\x00" * 64)

            matches = [
                _make_match("Malware_Generic", tags=["malware", "trojan"], meta={"author": "test"}),
                _make_match("Suspicious_Strings", tags=["suspicious"], meta={}),
            ]
            scanner._compiled.match.return_value = matches

            result = scanner.scan_file(str(target))

            assert len(result) == 2
            assert result[0]["rule"] == "Malware_Generic"
            assert result[0]["tags"] == ["malware", "trojan"]
            assert result[0]["meta"] == {"author": "test"}
            assert result[1]["rule"] == "Suspicious_Strings"
            # Verify match() called with resolved path and timeout
            scanner._compiled.match.assert_called_once()
            call_args = scanner._compiled.match.call_args
            assert call_args[0][0] == str(target.resolve())
            assert call_args[1]["timeout"] == 30
        finally:
            ctx.stop()

    def test_scan_file_too_large(self, tmp_path):
        """Files exceeding max_scan_size should be skipped."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(
            tmp_path, fake_yara, create_rules=True, max_scan_size=100,
        )
        try:
            target = tmp_path / "big.bin"
            target.write_bytes(b"X" * 200)

            result = scanner.scan_file(str(target))
            assert result == []
            scanner._compiled.match.assert_not_called()
        finally:
            ctx.stop()

    def test_scan_file_yara_error(self, tmp_path):
        """When yara.Error raised during scan, return []."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(tmp_path, fake_yara, create_rules=True)
        try:
            target = tmp_path / "corrupt.bin"
            target.write_bytes(b"data")

            scanner._compiled.match.side_effect = fake_yara.Error("scan failed")

            result = scanner.scan_file(str(target))
            assert result == []
        finally:
            ctx.stop()

    def test_scan_bytes_unavailable_returns_empty(self, tmp_path):
        """When yara not available, scan_bytes returns []."""
        ctx = patch.dict("sys.modules", {"yara": None})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))
            assert scanner.scan_bytes(b"payload data") == []
        finally:
            ctx.stop()

    def test_scan_bytes_no_rules_returns_empty(self, tmp_path):
        """When no rules compiled, scan_bytes returns []."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(tmp_path, fake_yara, create_rules=False)
        try:
            assert scanner.scan_bytes(b"payload data") == []
        finally:
            ctx.stop()

    def test_scan_bytes_with_matches(self, tmp_path):
        """scan_bytes returns dicts with rule/tags/meta from matches."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(tmp_path, fake_yara, create_rules=True)
        try:
            matches = [_make_match("Shellcode_Detect", tags=["exploit"], meta={"severity": "high"})]
            scanner._compiled.match.return_value = matches

            result = scanner.scan_bytes(b"\x90\x90\xcc\xcc")

            assert len(result) == 1
            assert result[0]["rule"] == "Shellcode_Detect"
            assert result[0]["tags"] == ["exploit"]
            assert result[0]["meta"] == {"severity": "high"}
            # Verify match() called with data= kwarg and timeout
            scanner._compiled.match.assert_called_once_with(
                data=b"\x90\x90\xcc\xcc", timeout=30,
            )
        finally:
            ctx.stop()

    def test_scan_bytes_too_large(self, tmp_path):
        """Data exceeding max_scan_size should be rejected."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(
            tmp_path, fake_yara, create_rules=True, max_scan_size=100,
        )
        try:
            result = scanner.scan_bytes(b"X" * 200)
            assert result == []
            scanner._compiled.match.assert_not_called()
        finally:
            ctx.stop()

    def test_scan_bytes_yara_error(self, tmp_path):
        """When yara.Error raised during in-memory scan, return []."""
        fake_yara = _make_fake_yara()
        scanner, ctx = _build_scanner(tmp_path, fake_yara, create_rules=True)
        try:
            scanner._compiled.match.side_effect = fake_yara.Error("buffer error")

            result = scanner.scan_bytes(b"bad data")
            assert result == []
        finally:
            ctx.stop()


# ---------------------------------------------------------------------------
# Test: reload_rules
# ---------------------------------------------------------------------------

class TestYaraScannerReload:
    """reload_rules() recompiles rules from disk."""

    def test_reload_updates_rules(self, tmp_path):
        """After adding a new .yar file, reload should pick it up."""
        (tmp_path / "initial.yar").write_text("rule init { condition: true }")

        fake_yara = _make_fake_yara()
        compiled_v1 = MagicMock(name="compiled_v1")
        compiled_v2 = MagicMock(name="compiled_v2")
        fake_yara.compile.side_effect = [compiled_v1, compiled_v2]

        ctx = patch.dict("sys.modules", {"yara": fake_yara})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))

            assert scanner.rules_count == 1
            assert scanner._compiled is compiled_v1

            # Add a second rule file and reload
            (tmp_path / "extra.yar").write_text("rule extra { condition: false }")
            scanner.reload_rules()

            assert scanner.rules_count == 2
            assert scanner._compiled is compiled_v2
            assert fake_yara.compile.call_count == 2
        finally:
            ctx.stop()

    def test_reload_when_unavailable(self, tmp_path):
        """reload_rules when yara not installed is a no-op."""
        ctx = patch.dict("sys.modules", {"yara": None})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))
        finally:
            ctx.stop()

        # Should not raise even outside the patched context
        scanner.reload_rules()
        assert scanner.is_available() is False

    def test_reload_clears_on_empty_dir(self, tmp_path):
        """If all .yar files removed, reload should clear _compiled."""
        (tmp_path / "temp.yar").write_text("rule temp { condition: true }")

        fake_yara = _make_fake_yara()
        compiled = MagicMock(name="compiled")
        fake_yara.compile.return_value = compiled

        ctx = patch.dict("sys.modules", {"yara": fake_yara})
        ctx.start()
        try:
            import netwatcher.analysis.yara_scanner as mod
            importlib.reload(mod)
            scanner = mod.YaraScanner(rules_dir=str(tmp_path))

            assert scanner._compiled is compiled
            assert scanner.rules_count == 1

            # Remove the rule file and reload
            (tmp_path / "temp.yar").unlink()
            scanner.reload_rules()

            assert scanner._compiled is None
            assert scanner.rules_count == 0
        finally:
            ctx.stop()
