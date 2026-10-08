import hashlib
import struct
from datetime import datetime, timezone
from pathlib import Path

import pytest

from irsys import db

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def conn(tmp_path, monkeypatch):
    monkeypatch.setenv("IRSYS_HOME", str(tmp_path / "home"))
    c = db.connect()
    yield c
    c.close()


def build_pe(timestamp: datetime) -> bytes:
    """실행 코드가 없는 최소 PE32(가져오기: VirtualAlloc, WriteProcessMemory)를 만든다."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    coff = struct.pack("<HHIIIHH", 0x14C, 2, int(timestamp.timestamp()), 0, 0, 224, 0x0102)
    opt = bytearray(224)
    struct.pack_into("<H", opt, 0, 0x10B)
    struct.pack_into("<I", opt, 16, 0x1000)       # 진입점
    struct.pack_into("<I", opt, 28, 0x400000)     # ImageBase
    struct.pack_into("<II", opt, 32, 0x1000, 0x200)
    struct.pack_into("<H", opt, 68, 2)            # GUI
    struct.pack_into("<I", opt, 92, 16)
    struct.pack_into("<II", opt, 96 + 8, 0x2000, 40)  # 가져오기 디렉터리

    def section(name, vsize, va, rsize, rptr, chars):
        return name.ljust(8, b"\x00") + struct.pack("<IIII", vsize, va, rsize, rptr) + bytes(12) + struct.pack("<I", chars)

    headers = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt)
    headers += section(b".text", 0x200, 0x1000, 0x200, 0x200, 0x60000020)
    headers += section(b".idata", 0x200, 0x2000, 0x200, 0x400, 0xC0000040)
    headers = headers.ljust(0x200, b"\x00")

    text = bytearray(0x200)
    pdb = b"C:\\Users\\dev\\Desktop\\work\\Release\\loader.pdb\x00"
    text[0:len(pdb)] = pdb
    kor = "자료수집 모듈".encode("utf-16le") + b"\x00\x00"
    text[0x80:0x80 + len(kor)] = kor

    idata = bytearray(0x200)
    struct.pack_into("<IIIII", idata, 0, 0x2040, 0, 0, 0x2080, 0x2040)
    struct.pack_into("<III", idata, 0x40, 0x20A0, 0x20C0, 0)
    idata[0x80:0x80 + 13] = b"KERNEL32.dll\x00"
    idata[0xA2:0xA2 + 13] = b"VirtualAlloc\x00"
    idata[0xC2:0xC2 + 19] = b"WriteProcessMemory\x00"
    return headers + bytes(text) + bytes(idata)


@pytest.fixture()
def pe_file(tmp_path) -> Path:
    p = tmp_path / "loader.exe.bin"
    p.write_bytes(build_pe(datetime(2026, 3, 3, 2, 0, tzinfo=timezone.utc)))  # KST 화요일 11시
    return p


EXPECTED_IMPHASH = hashlib.md5(b"kernel32.virtualalloc,kernel32.writeprocessmemory").hexdigest()
