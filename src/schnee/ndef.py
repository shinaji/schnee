"""Shared NDEF data models."""

from __future__ import annotations

from enum import StrEnum, unique
from typing import NewType

NdefUriPrefixCode = NewType("NdefUriPrefixCode", int)
NdefUriExpandedText = NewType("NdefUriExpandedText", str)


@unique
class NdefUriPrefix(StrEnum):
    """NDEF URI Identifier Code prefix table."""

    NO_PREFIX = "no_prefix"
    HTTP_WWW = "http_www"
    HTTPS_WWW = "https_www"
    HTTP = "http"
    HTTPS = "https"
    TEL = "tel"
    MAILTO = "mailto"
    FTP_ANONYMOUS = "ftp_anonymous"
    FTP_FTP = "ftp_ftp"
    FTPS = "ftps"
    SFTP = "sftp"
    SMB = "smb"
    NFS = "nfs"
    FTP = "ftp"
    DAV = "dav"
    NEWS = "news"
    TELNET = "telnet"
    IMAP = "imap"
    RTSP = "rtsp"
    URN = "urn"
    POP = "pop"
    SIP = "sip"
    SIPS = "sips"
    TFTP = "tftp"
    BTSPP = "btspp"
    BTL2CAP = "btl2cap"
    BTGOEP = "btgoep"
    TCPOBEX = "tcpobex"
    IRDAOBEX = "irdaobex"
    FILE = "file"
    URN_EPC_ID = "urn_epc_id"
    URN_EPC_TAG = "urn_epc_tag"
    URN_EPC_PAT = "urn_epc_pat"
    URN_EPC_RAW = "urn_epc_raw"
    URN_EPC = "urn_epc"
    URN_NFC = "urn_nfc"

    @property
    def code(self) -> NdefUriPrefixCode:
        """Return the numeric URI Identifier Code."""
        return _NDEF_URI_PREFIX_CODES[self]

    @property
    def expanded_text(self) -> NdefUriExpandedText:
        """Return the expanded text represented by the prefix code."""
        return _NDEF_URI_PREFIX_TEXT[self]

    @classmethod
    def from_code(cls, code: int) -> NdefUriPrefix:
        """Return the URI prefix for a numeric URI Identifier Code."""
        try:
            return _NDEF_URI_PREFIXES_BY_CODE[NdefUriPrefixCode(code)]
        except KeyError:
            msg = f"Unsupported URI identifier code: {code:#x}"
            raise ValueError(msg) from None


_NDEF_URI_PREFIX_CODES: dict[NdefUriPrefix, NdefUriPrefixCode] = {
    NdefUriPrefix.NO_PREFIX: NdefUriPrefixCode(0x00),
    NdefUriPrefix.HTTP_WWW: NdefUriPrefixCode(0x01),
    NdefUriPrefix.HTTPS_WWW: NdefUriPrefixCode(0x02),
    NdefUriPrefix.HTTP: NdefUriPrefixCode(0x03),
    NdefUriPrefix.HTTPS: NdefUriPrefixCode(0x04),
    NdefUriPrefix.TEL: NdefUriPrefixCode(0x05),
    NdefUriPrefix.MAILTO: NdefUriPrefixCode(0x06),
    NdefUriPrefix.FTP_ANONYMOUS: NdefUriPrefixCode(0x07),
    NdefUriPrefix.FTP_FTP: NdefUriPrefixCode(0x08),
    NdefUriPrefix.FTPS: NdefUriPrefixCode(0x09),
    NdefUriPrefix.SFTP: NdefUriPrefixCode(0x0A),
    NdefUriPrefix.SMB: NdefUriPrefixCode(0x0B),
    NdefUriPrefix.NFS: NdefUriPrefixCode(0x0C),
    NdefUriPrefix.FTP: NdefUriPrefixCode(0x0D),
    NdefUriPrefix.DAV: NdefUriPrefixCode(0x0E),
    NdefUriPrefix.NEWS: NdefUriPrefixCode(0x0F),
    NdefUriPrefix.TELNET: NdefUriPrefixCode(0x10),
    NdefUriPrefix.IMAP: NdefUriPrefixCode(0x11),
    NdefUriPrefix.RTSP: NdefUriPrefixCode(0x12),
    NdefUriPrefix.URN: NdefUriPrefixCode(0x13),
    NdefUriPrefix.POP: NdefUriPrefixCode(0x14),
    NdefUriPrefix.SIP: NdefUriPrefixCode(0x15),
    NdefUriPrefix.SIPS: NdefUriPrefixCode(0x16),
    NdefUriPrefix.TFTP: NdefUriPrefixCode(0x17),
    NdefUriPrefix.BTSPP: NdefUriPrefixCode(0x18),
    NdefUriPrefix.BTL2CAP: NdefUriPrefixCode(0x19),
    NdefUriPrefix.BTGOEP: NdefUriPrefixCode(0x1A),
    NdefUriPrefix.TCPOBEX: NdefUriPrefixCode(0x1B),
    NdefUriPrefix.IRDAOBEX: NdefUriPrefixCode(0x1C),
    NdefUriPrefix.FILE: NdefUriPrefixCode(0x1D),
    NdefUriPrefix.URN_EPC_ID: NdefUriPrefixCode(0x1E),
    NdefUriPrefix.URN_EPC_TAG: NdefUriPrefixCode(0x1F),
    NdefUriPrefix.URN_EPC_PAT: NdefUriPrefixCode(0x20),
    NdefUriPrefix.URN_EPC_RAW: NdefUriPrefixCode(0x21),
    NdefUriPrefix.URN_EPC: NdefUriPrefixCode(0x22),
    NdefUriPrefix.URN_NFC: NdefUriPrefixCode(0x23),
}

_NDEF_URI_PREFIX_TEXT: dict[NdefUriPrefix, NdefUriExpandedText] = {
    NdefUriPrefix.NO_PREFIX: NdefUriExpandedText(""),
    NdefUriPrefix.HTTP_WWW: NdefUriExpandedText("http://www."),
    NdefUriPrefix.HTTPS_WWW: NdefUriExpandedText("https://www."),
    NdefUriPrefix.HTTP: NdefUriExpandedText("http://"),
    NdefUriPrefix.HTTPS: NdefUriExpandedText("https://"),
    NdefUriPrefix.TEL: NdefUriExpandedText("tel:"),
    NdefUriPrefix.MAILTO: NdefUriExpandedText("mailto:"),
    NdefUriPrefix.FTP_ANONYMOUS: NdefUriExpandedText("ftp://anonymous:anonymous@"),
    NdefUriPrefix.FTP_FTP: NdefUriExpandedText("ftp://ftp."),
    NdefUriPrefix.FTPS: NdefUriExpandedText("ftps://"),
    NdefUriPrefix.SFTP: NdefUriExpandedText("sftp://"),
    NdefUriPrefix.SMB: NdefUriExpandedText("smb://"),
    NdefUriPrefix.NFS: NdefUriExpandedText("nfs://"),
    NdefUriPrefix.FTP: NdefUriExpandedText("ftp://"),
    NdefUriPrefix.DAV: NdefUriExpandedText("dav://"),
    NdefUriPrefix.NEWS: NdefUriExpandedText("news:"),
    NdefUriPrefix.TELNET: NdefUriExpandedText("telnet://"),
    NdefUriPrefix.IMAP: NdefUriExpandedText("imap:"),
    NdefUriPrefix.RTSP: NdefUriExpandedText("rtsp://"),
    NdefUriPrefix.URN: NdefUriExpandedText("urn:"),
    NdefUriPrefix.POP: NdefUriExpandedText("pop:"),
    NdefUriPrefix.SIP: NdefUriExpandedText("sip:"),
    NdefUriPrefix.SIPS: NdefUriExpandedText("sips:"),
    NdefUriPrefix.TFTP: NdefUriExpandedText("tftp:"),
    NdefUriPrefix.BTSPP: NdefUriExpandedText("btspp://"),
    NdefUriPrefix.BTL2CAP: NdefUriExpandedText("btl2cap://"),
    NdefUriPrefix.BTGOEP: NdefUriExpandedText("btgoep://"),
    NdefUriPrefix.TCPOBEX: NdefUriExpandedText("tcpobex://"),
    NdefUriPrefix.IRDAOBEX: NdefUriExpandedText("irdaobex://"),
    NdefUriPrefix.FILE: NdefUriExpandedText("file://"),
    NdefUriPrefix.URN_EPC_ID: NdefUriExpandedText("urn:epc:id:"),
    NdefUriPrefix.URN_EPC_TAG: NdefUriExpandedText("urn:epc:tag:"),
    NdefUriPrefix.URN_EPC_PAT: NdefUriExpandedText("urn:epc:pat:"),
    NdefUriPrefix.URN_EPC_RAW: NdefUriExpandedText("urn:epc:raw:"),
    NdefUriPrefix.URN_EPC: NdefUriExpandedText("urn:epc:"),
    NdefUriPrefix.URN_NFC: NdefUriExpandedText("urn:nfc:"),
}

_NDEF_URI_PREFIXES_BY_CODE: dict[NdefUriPrefixCode, NdefUriPrefix] = {
    prefix.code: prefix for prefix in NdefUriPrefix
}
