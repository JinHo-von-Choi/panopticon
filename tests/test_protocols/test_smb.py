"""Tests for SMBv2/v3 protocol parsers."""

import struct

from netwatcher.protocols.smb import (
    parse_smb2,
    parse_smb2_negotiate,
    parse_smb2_tree_connect,
    is_null_session,
)

# SMB2 매직
_SMB2_MAGIC = b"\xfeSMB"


def _build_smb2_header(
    command: int = 0x0000,
    flags: int = 0x00000000,
    message_id: int = 0,
    tree_id: int = 0,
    session_id: int = 0,
) -> bytes:
    """64바이트 SMB2 헤더를 조립한다."""
    buf = bytearray(64)
    buf[0:4] = _SMB2_MAGIC
    struct.pack_into("<H", buf, 4, 64)       # StructureSize
    # CreditCharge(2) + Status(4) = offset 6..11
    struct.pack_into("<H", buf, 12, command)  # Command
    # CreditRequest(2) = offset 14
    struct.pack_into("<I", buf, 16, flags)    # Flags
    # NextCommand(4) = offset 20
    struct.pack_into("<Q", buf, 24, message_id)  # MessageId
    # Reserved(4) = offset 32
    struct.pack_into("<I", buf, 36, tree_id)     # TreeId
    struct.pack_into("<Q", buf, 40, session_id)  # SessionId
    # Signature(16) = offset 48
    return bytes(buf)


class TestParseSMB2:
    """SMB2 헤더 파싱 테스트."""

    def test_negotiate_request(self):
        payload = _build_smb2_header(command=0x0000)
        result = parse_smb2(payload)
        assert result is not None
        assert result["command"] == "NEGOTIATE"
        assert result["command_id"] == 0
        assert result["is_response"] is False
        assert result["version"] == "SMB2"

    def test_session_setup_response(self):
        payload = _build_smb2_header(
            command=0x0001, flags=0x00000001, session_id=0xDEAD
        )
        result = parse_smb2(payload)
        assert result is not None
        assert result["command"] == "SESSION_SETUP"
        assert result["is_response"] is True
        assert result["session_id"] == 0xDEAD

    def test_tree_connect(self):
        payload = _build_smb2_header(command=0x0003, tree_id=42)
        result = parse_smb2(payload)
        assert result is not None
        assert result["command"] == "TREE_CONNECT"
        assert result["tree_id"] == 42

    def test_create_command(self):
        payload = _build_smb2_header(command=0x0005)
        result = parse_smb2(payload)
        assert result is not None
        assert result["command"] == "CREATE"

    def test_read_write(self):
        for cmd, name in [(0x0008, "READ"), (0x0009, "WRITE")]:
            result = parse_smb2(_build_smb2_header(command=cmd))
            assert result is not None
            assert result["command"] == name

    def test_message_id(self):
        payload = _build_smb2_header(message_id=12345)
        result = parse_smb2(payload)
        assert result is not None
        assert result["message_id"] == 12345

    def test_unknown_command(self):
        payload = _build_smb2_header(command=0xFFFF)
        result = parse_smb2(payload)
        assert result is not None
        assert "UNKNOWN" in result["command"]

    def test_wrong_magic_returns_none(self):
        payload = b"\xffSMB" + b"\x00" * 60
        assert parse_smb2(payload) is None

    def test_wrong_structure_size_returns_none(self):
        buf = bytearray(64)
        buf[0:4] = _SMB2_MAGIC
        struct.pack_into("<H", buf, 4, 32)  # 잘못된 크기
        assert parse_smb2(bytes(buf)) is None

    def test_truncated_returns_none(self):
        assert parse_smb2(b"") is None
        assert parse_smb2(_SMB2_MAGIC + b"\x00" * 10) is None

    def test_smb1_magic_returns_none(self):
        # SMB1 매직: 0xFF 'S' 'M' 'B'
        payload = b"\xffSMB" + b"\x00" * 60
        assert parse_smb2(payload) is None


class TestParseSMB2Negotiate:
    """SMB2 NEGOTIATE 요청 파싱 테스트."""

    def _build_negotiate(self, dialects: list[int], security_mode: int = 1) -> bytes:
        """NEGOTIATE 요청 패킷을 조립한다."""
        header = _build_smb2_header(command=0x0000)

        # Negotiate 요청 구조 (36바이트 고정 필드 + dialects)
        neg = bytearray(36 + len(dialects) * 2)
        struct.pack_into("<H", neg, 0, 36)              # StructureSize
        struct.pack_into("<H", neg, 2, len(dialects))   # DialectCount
        struct.pack_into("<H", neg, 4, security_mode)   # SecurityMode
        # Reserved(2) + Capabilities(4) + ClientGuid(16) + contexts(8)
        for i, d in enumerate(dialects):
            struct.pack_into("<H", neg, 36 + i * 2, d)

        return header + bytes(neg)

    def test_single_dialect(self):
        payload = self._build_negotiate([0x0311])
        result = parse_smb2_negotiate(payload)
        assert result is not None
        assert "SMB 3.1.1" in result["dialects"]
        assert result["security_mode"] == 1

    def test_multiple_dialects(self):
        payload = self._build_negotiate([0x0202, 0x0210, 0x0300, 0x0311])
        result = parse_smb2_negotiate(payload)
        assert result is not None
        assert len(result["dialects"]) == 4
        assert "SMB 2.0.2" in result["dialects"]
        assert "SMB 3.1.1" in result["dialects"]

    def test_unknown_dialect(self):
        payload = self._build_negotiate([0x9999])
        result = parse_smb2_negotiate(payload)
        assert result is not None
        assert "0x9999" in result["dialects"][0]

    def test_non_negotiate_returns_none(self):
        payload = _build_smb2_header(command=0x0001) + b"\x00" * 40
        assert parse_smb2_negotiate(payload) is None

    def test_response_returns_none(self):
        header = _build_smb2_header(command=0x0000, flags=0x00000001)
        neg = b"\x00" * 40
        assert parse_smb2_negotiate(header + neg) is None

    def test_truncated_returns_none(self):
        assert parse_smb2_negotiate(b"") is None


class TestParseSMB2TreeConnect:
    """SMB2 TREE_CONNECT 요청 파싱 테스트."""

    def _build_tree_connect(
        self, share_path: str, session_id: int = 1
    ) -> bytes:
        """TREE_CONNECT 요청 패킷을 조립한다."""
        header = _build_smb2_header(
            command=0x0003, session_id=session_id
        )
        path_bytes = share_path.encode("utf-16-le")

        # TreeConnect 요청: StructureSize(2) + Flags(2) + PathOffset(2) + PathLength(2)
        tc = bytearray(8)
        path_offset = 64 + 8  # 헤더(64) + TC 고정(8)
        struct.pack_into("<H", tc, 0, 9)              # StructureSize
        struct.pack_into("<H", tc, 2, 0)              # Flags/Reserved
        struct.pack_into("<H", tc, 4, path_offset)    # PathOffset
        struct.pack_into("<H", tc, 6, len(path_bytes))  # PathLength

        return header + bytes(tc) + path_bytes

    def test_ipc_share(self):
        payload = self._build_tree_connect("\\\\server\\IPC$")
        result = parse_smb2_tree_connect(payload)
        assert result is not None
        assert "IPC$" in result["share_path"]

    def test_regular_share(self):
        payload = self._build_tree_connect("\\\\fileserver\\share")
        result = parse_smb2_tree_connect(payload)
        assert result is not None
        assert result["share_path"] == "\\\\fileserver\\share"

    def test_non_tree_connect_returns_none(self):
        payload = _build_smb2_header(command=0x0000) + b"\x00" * 40
        assert parse_smb2_tree_connect(payload) is None

    def test_response_returns_none(self):
        header = _build_smb2_header(command=0x0003, flags=0x00000001)
        assert parse_smb2_tree_connect(header + b"\x00" * 40) is None

    def test_truncated_returns_none(self):
        assert parse_smb2_tree_connect(b"") is None


class TestIsNullSession:
    """SMB NULL 세션 탐지 테스트."""

    def _build_tree_connect(
        self, share_path: str, session_id: int = 0
    ) -> bytes:
        header = _build_smb2_header(
            command=0x0003, session_id=session_id
        )
        path_bytes = share_path.encode("utf-16-le")
        tc = bytearray(8)
        path_offset = 64 + 8
        struct.pack_into("<H", tc, 0, 9)
        struct.pack_into("<H", tc, 4, path_offset)
        struct.pack_into("<H", tc, 6, len(path_bytes))
        return header + bytes(tc) + path_bytes

    def test_null_session_ipc(self):
        payload = self._build_tree_connect("\\\\server\\IPC$", session_id=0)
        assert is_null_session(payload) is True

    def test_non_null_session(self):
        payload = self._build_tree_connect("\\\\server\\IPC$", session_id=42)
        assert is_null_session(payload) is False

    def test_non_ipc_share(self):
        payload = self._build_tree_connect("\\\\server\\share", session_id=0)
        assert is_null_session(payload) is False

    def test_non_smb_returns_false(self):
        assert is_null_session(b"\x00" * 100) is False

    def test_empty_returns_false(self):
        assert is_null_session(b"") is False
