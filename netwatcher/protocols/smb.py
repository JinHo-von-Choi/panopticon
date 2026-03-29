"""단일 패킷 검사용 경량 SMBv2/v3 파서.

처음 2048 바이트만 파싱한다. SMB가 아니거나
형식이 올바르지 않거나 잘린 페이로드의 경우 None을 반환한다.
"""

from __future__ import annotations

import struct

_MAX_PAYLOAD_BYTES = 2048

# SMB2 매직 바이트: 0xFE 'S' 'M' 'B'
_SMB2_MAGIC = b"\xfeSMB"

# SMB2 헤더 크기
_SMB2_HEADER_SIZE = 64

# SMB2 명령 코드
_SMB2_COMMAND_NEGOTIATE      = 0x0000
_SMB2_COMMAND_SESSION_SETUP  = 0x0001
_SMB2_COMMAND_LOGOFF         = 0x0002
_SMB2_COMMAND_TREE_CONNECT   = 0x0003
_SMB2_COMMAND_TREE_DISCONNECT = 0x0004
_SMB2_COMMAND_CREATE         = 0x0005
_SMB2_COMMAND_CLOSE          = 0x0006
_SMB2_COMMAND_FLUSH          = 0x0007
_SMB2_COMMAND_READ           = 0x0008
_SMB2_COMMAND_WRITE          = 0x0009
_SMB2_COMMAND_LOCK           = 0x000A
_SMB2_COMMAND_IOCTL          = 0x000B
_SMB2_COMMAND_CANCEL         = 0x000C
_SMB2_COMMAND_ECHO           = 0x000D
_SMB2_COMMAND_QUERY_DIRECTORY = 0x000E
_SMB2_COMMAND_CHANGE_NOTIFY  = 0x000F
_SMB2_COMMAND_QUERY_INFO     = 0x0010
_SMB2_COMMAND_SET_INFO       = 0x0011

_SMB2_COMMAND_NAMES = {
    _SMB2_COMMAND_NEGOTIATE:       "NEGOTIATE",
    _SMB2_COMMAND_SESSION_SETUP:   "SESSION_SETUP",
    _SMB2_COMMAND_LOGOFF:          "LOGOFF",
    _SMB2_COMMAND_TREE_CONNECT:    "TREE_CONNECT",
    _SMB2_COMMAND_TREE_DISCONNECT: "TREE_DISCONNECT",
    _SMB2_COMMAND_CREATE:          "CREATE",
    _SMB2_COMMAND_CLOSE:           "CLOSE",
    _SMB2_COMMAND_FLUSH:           "FLUSH",
    _SMB2_COMMAND_READ:            "READ",
    _SMB2_COMMAND_WRITE:           "WRITE",
    _SMB2_COMMAND_LOCK:            "LOCK",
    _SMB2_COMMAND_IOCTL:           "IOCTL",
    _SMB2_COMMAND_CANCEL:          "CANCEL",
    _SMB2_COMMAND_ECHO:            "ECHO",
    _SMB2_COMMAND_QUERY_DIRECTORY: "QUERY_DIRECTORY",
    _SMB2_COMMAND_CHANGE_NOTIFY:   "CHANGE_NOTIFY",
    _SMB2_COMMAND_QUERY_INFO:      "QUERY_INFO",
    _SMB2_COMMAND_SET_INFO:        "SET_INFO",
}

# SMB2 Flags 비트
_SMB2_FLAGS_SERVER_TO_REDIR = 0x00000001  # Response 플래그

# SMB2 Dialect 값
_SMB2_DIALECT_NAMES = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
}


def parse_smb2(payload: bytes) -> dict | None:
    """SMBv2/v3 헤더를 파싱하여 명령 정보를 추출한다.

    {"version": str, "command": str, "command_id": int,
     "flags": int, "is_response": bool, "message_id": int,
     "tree_id": int, "session_id": int} 또는 None을 반환한다.
    """
    if not payload or len(payload) < _SMB2_HEADER_SIZE:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]

    # SMB2 매직 확인
    if data[:4] != _SMB2_MAGIC:
        return None

    # StructureSize (offset 4, 2 bytes LE) - 항상 64
    structure_size = struct.unpack("<H", data[4:6])[0]
    if structure_size != _SMB2_HEADER_SIZE:
        return None

    # Command (offset 12, 2 bytes LE)
    command_id = struct.unpack("<H", data[12:14])[0]
    command_name = _SMB2_COMMAND_NAMES.get(command_id, f"UNKNOWN(0x{command_id:04X})")

    # Flags (offset 16, 4 bytes LE)
    flags = struct.unpack("<I", data[16:20])[0]
    is_response = bool(flags & _SMB2_FLAGS_SERVER_TO_REDIR)

    # MessageId (offset 24, 8 bytes LE)
    message_id = struct.unpack("<Q", data[24:32])[0]

    # TreeId (offset 36, 4 bytes LE)
    tree_id = struct.unpack("<I", data[36:40])[0]

    # SessionId (offset 40, 8 bytes LE)
    session_id = struct.unpack("<Q", data[40:48])[0]

    # 버전 판별: 3.x 기능을 사용하면 SMB3, 아니면 SMB2
    # 간이 판별 -- Negotiate 응답이 아닌 이상 정확한 dialect은
    # 알 수 없으므로 헤더만으로는 SMB2로 표기한다
    version = "SMB2"

    return {
        "version":    version,
        "command":    command_name,
        "command_id": command_id,
        "flags":      flags,
        "is_response": is_response,
        "message_id": message_id,
        "tree_id":    tree_id,
        "session_id": session_id,
    }


def parse_smb2_negotiate(payload: bytes) -> dict | None:
    """SMB2 NEGOTIATE 요청에서 지원 dialect 목록을 추출한다.

    {"dialects": list[str], "security_mode": int} 또는 None을 반환한다.
    """
    header = parse_smb2(payload)
    if header is None:
        return None

    if header["command_id"] != _SMB2_COMMAND_NEGOTIATE:
        return None

    # Response는 대상이 아님
    if header["is_response"]:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]

    # Negotiate 요청 구조 (헤더 64바이트 이후):
    # StructureSize(2) + DialectCount(2) + SecurityMode(2)
    # + Reserved(2) + Capabilities(4) + ClientGuid(16)
    # + NegotiateContextOffset(4) + NegotiateContextCount(2) + Reserved2(2)
    # + Dialects(DialectCount * 2)
    neg_offset = _SMB2_HEADER_SIZE
    if len(data) < neg_offset + 8:
        return None

    dialect_count = struct.unpack("<H", data[neg_offset + 2:neg_offset + 4])[0]
    security_mode = struct.unpack("<H", data[neg_offset + 4:neg_offset + 6])[0]

    # Dialects 시작 위치: 헤더(64) + 고정 필드(36)
    dialects_offset = neg_offset + 36
    dialects: list[str] = []

    for i in range(dialect_count):
        d_off = dialects_offset + (i * 2)
        if d_off + 2 > len(data):
            break
        dialect_value = struct.unpack("<H", data[d_off:d_off + 2])[0]
        dialect_name = _SMB2_DIALECT_NAMES.get(
            dialect_value, f"0x{dialect_value:04X}"
        )
        dialects.append(dialect_name)

    return {
        "dialects":      dialects,
        "security_mode": security_mode,
    }


def parse_smb2_tree_connect(payload: bytes) -> dict | None:
    """SMB2 TREE_CONNECT 요청에서 공유 경로를 추출한다.

    {"share_path": str} 또는 None을 반환한다.
    """
    header = parse_smb2(payload)
    if header is None:
        return None

    if header["command_id"] != _SMB2_COMMAND_TREE_CONNECT:
        return None

    if header["is_response"]:
        return None

    data = payload[:_MAX_PAYLOAD_BYTES]

    # TreeConnect 요청 구조 (헤더 64바이트 이후):
    # StructureSize(2) + Reserved/Flags(2) + PathOffset(2) + PathLength(2)
    tc_offset = _SMB2_HEADER_SIZE
    if len(data) < tc_offset + 8:
        return None

    path_offset = struct.unpack("<H", data[tc_offset + 4:tc_offset + 6])[0]
    path_length = struct.unpack("<H", data[tc_offset + 6:tc_offset + 8])[0]

    if path_offset == 0 or path_length == 0:
        return None

    if path_offset + path_length > len(data):
        return None

    try:
        share_path = data[path_offset:path_offset + path_length].decode(
            "utf-16-le", errors="replace"
        ).rstrip("\x00")
    except (UnicodeDecodeError, ValueError):
        return None

    return {"share_path": share_path}


def is_null_session(payload: bytes) -> bool:
    """SMB NULL 세션 시도(IPC$에 대한 익명 접근)를 탐지한다.

    SESSION_SETUP 후 TREE_CONNECT에서 IPC$ 경로가 확인되고
    session_id가 0이면 NULL 세션 시도로 간주한다.
    """
    tc_result = parse_smb2_tree_connect(payload)
    if tc_result is None:
        return False

    share_path = tc_result["share_path"].upper()

    # IPC$ 공유 확인
    if not share_path.endswith("IPC$"):
        return False

    # 헤더에서 session_id 확인
    header = parse_smb2(payload)
    if header is None:
        return False

    return header["session_id"] == 0
