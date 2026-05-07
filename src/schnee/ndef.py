"""Shared NDEF data models."""

from __future__ import annotations

from enum import Enum, unique


@unique
class NdefUriPrefix(Enum):
    """NDEF URI Identifier Code prefix table."""

    NO_PREFIX = (0x00, "")
    HTTP_WWW = (0x01, "http://www.")
    HTTPS_WWW = (0x02, "https://www.")
    HTTP = (0x03, "http://")
    HTTPS = (0x04, "https://")
    TEL = (0x05, "tel:")
    MAILTO = (0x06, "mailto:")
    FTP_ANONYMOUS = (0x07, "ftp://anonymous:anonymous@")
    FTP_FTP = (0x08, "ftp://ftp.")
    FTPS = (0x09, "ftps://")
    SFTP = (0x0A, "sftp://")
    SMB = (0x0B, "smb://")
    NFS = (0x0C, "nfs://")
    FTP = (0x0D, "ftp://")
    DAV = (0x0E, "dav://")
    NEWS = (0x0F, "news:")
    TELNET = (0x10, "telnet://")
    IMAP = (0x11, "imap:")
    RTSP = (0x12, "rtsp://")
    URN = (0x13, "urn:")
    POP = (0x14, "pop:")
    SIP = (0x15, "sip:")
    SIPS = (0x16, "sips:")
    TFTP = (0x17, "tftp:")
    BTSPP = (0x18, "btspp://")
    BTL2CAP = (0x19, "btl2cap://")
    BTGOEP = (0x1A, "btgoep://")
    TCPOBEX = (0x1B, "tcpobex://")
    IRDAOBEX = (0x1C, "irdaobex://")
    FILE = (0x1D, "file://")
    URN_EPC_ID = (0x1E, "urn:epc:id:")
    URN_EPC_TAG = (0x1F, "urn:epc:tag:")
    URN_EPC_PAT = (0x20, "urn:epc:pat:")
    URN_EPC_RAW = (0x21, "urn:epc:raw:")
    URN_EPC = (0x22, "urn:epc:")
    URN_NFC = (0x23, "urn:nfc:")

    def __init__(self, code: int, expanded_text: str) -> None:
        self._code = code
        self._expanded_text = expanded_text

    @property
    def code(self) -> int:
        """Return the numeric URI Identifier Code."""
        return self._code

    @property
    def expanded_text(self) -> str:
        """Return the expanded text represented by the prefix code."""
        return self._expanded_text

    @classmethod
    def from_code(cls, code: int) -> NdefUriPrefix:
        """Return the URI prefix for a numeric URI Identifier Code."""
        try:
            return _NDEF_URI_PREFIXES_BY_CODE[code]
        except KeyError:
            msg = f"Unsupported URI identifier code: {code:#x}"
            raise ValueError(msg) from None


_NDEF_URI_PREFIXES_BY_CODE: dict[int, NdefUriPrefix] = {
    prefix.code: prefix for prefix in NdefUriPrefix
}
