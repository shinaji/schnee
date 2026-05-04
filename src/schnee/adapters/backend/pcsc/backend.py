from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from smartcard.Exceptions import CardConnectionException

from schnee.adapters.ntag.apdu import (
    Ntag424ApduPreset,
    Ntag424FileSettings,
    PcscContactlessApduPreset,
)
from schnee.adapters.ntag.profile import (
    ChangePlan,
    NdefProfile,
    NdefProfileParser,
    Ntag21xProfile,
    Ntag424DnaProfile,
    Ntag424ProfileSections,
    NtagProfile,
    TagInfo,
    TagType,
)
from schnee.adapters.ntag.utils import int_to_3bytes_le

from .client import PcscApduClient
from .reader import PcscConnection, PcscReader, PcscReaderProvider

if TYPE_CHECKING:
    from schnee.adapters.ntag.apdu import CommandAPDU, ResponseAPDU


class PcscBackend:
    """Backend adapter that wraps a PC/SC reader."""

    ntag_application_df_name: ClassVar[list[int]] = [
        0xD2,
        0x76,
        0x00,
        0x00,
        0x85,
        0x01,
        0x01,
    ]
    ndef_file_no: ClassVar[int] = 0x02
    ndef_length_header_size: ClassVar[int] = 2
    ntag424_key_slots: ClassVar[int] = 5
    type2_cc_page: ClassVar[int] = 3
    type2_ndef_start_page: ClassVar[int] = 4
    type2_page_size: ClassVar[int] = 4
    type2_null_tlv: ClassVar[int] = 0x00
    type2_ndef_tlv: ClassVar[int] = 0x03
    type2_terminator_tlv: ClassVar[int] = 0xFE
    type2_extended_tlv_length: ClassVar[int] = 0xFF
    type2_capacity_types: ClassVar[dict[int, TagType]] = {
        144: "NTAG213",
        496: "NTAG215",
        888: "NTAG216",
    }

    class PcscBackendError(Exception):
        """PC/SC backend error."""

    class UnsupportedPlanError(PcscBackendError):
        """Raised when a write plan is not implemented by the PC/SC backend."""

    class UnsupportedProfileReadError(PcscBackendError):
        """Raised when full profile reads are not implemented."""

    class NdefParseError(PcscBackendError):
        """Raised when NDEF data cannot be represented as a profile."""

    def __init__(self, reader: PcscReader) -> None:
        self.reader = reader
        self.client = PcscApduClient(reader)

    @property
    def reader_name(self) -> str:
        """Return the wrapped PC/SC reader name."""
        return self.client.reader_name

    def connect(self) -> PcscConnection:
        """Connect to the wrapped PC/SC reader."""
        return self.client.connect()

    def send_apdu(self, apdu: CommandAPDU | list[int]) -> ResponseAPDU:
        """Transmit an APDU through the wrapped PC/SC reader."""
        return self.client.send_apdu(apdu)

    def read_profile(self) -> NtagProfile:
        """Read the currently reachable NTAG profile."""
        uid = self._read_uid()
        try:
            self._select_ntag_application()
        except CardConnectionException, PcscApduClient.PcscApduClientError:
            return self._read_type2_profile(uid)

        file_settings = Ntag424FileSettings.from_response(
            self._get_file_settings(self.ndef_file_no),
        )
        sections = Ntag424ProfileSections.from_parsed_data(
            file_settings=file_settings,
            key_versions=self._get_key_versions(),
        )
        return Ntag424DnaProfile(
            tag=TagInfo(type="NTAG424DNA", uid=uid),
            ndef=self._read_ndef_profile(),
            sdm=sections.sdm,
            access=sections.access,
            security=sections.security,
            locks=sections.locks,
        )

    def read_tag_info(self) -> TagInfo:
        """Read the currently reachable NTAG tag identity summary."""
        uid = self._read_uid()
        try:
            self._select_ntag_application()
        except CardConnectionException, PcscApduClient.PcscApduClientError:
            return self._read_type2_tag_info(uid)
        return TagInfo(type="NTAG424DNA", uid=uid)

    def apply_plan(self, plan: ChangePlan) -> Ntag424DnaProfile:
        """Apply a profile change plan through PC/SC."""
        _ = plan
        msg = "PC/SC profile writes are not implemented yet"
        raise self.UnsupportedPlanError(msg)

    def _read_uid(self) -> str:
        """Read UID using the common PC/SC contactless reader command."""
        response = self.send_apdu(PcscContactlessApduPreset.get_uid())
        if not response.ok:
            msg = f"Unable to read tag UID: status {response.status:#x}"
            raise self.UnsupportedProfileReadError(msg)
        return bytes(response.data).hex().upper()

    def _select_ntag_application(self) -> None:
        """Select the NTAG 424 DNA application by DF name."""
        self.client.send_checked(
            Ntag424ApduPreset.select_application(self.ntag_application_df_name),
        )

    def _read_ndef_profile(self) -> NdefProfile:
        """Read and parse the NDEF file into profile records."""
        length_data = self._read_data_file(
            file_no=self.ndef_file_no,
            offset=0,
            length=self.ndef_length_header_size,
        )
        if len(length_data) != self.ndef_length_header_size:
            msg = "NDEF file length header must be 2 bytes"
            raise self.NdefParseError(msg)

        ndef_length = int.from_bytes(bytes(length_data), byteorder="big")
        if ndef_length == 0:
            return NdefProfile(present=False)

        message = self._read_data_file(
            file_no=self.ndef_file_no,
            offset=2,
            length=ndef_length,
        )
        try:
            records = NdefProfileParser.parse_message(message)
        except NdefProfileParser.NdefParseError as exc:
            raise self.NdefParseError(str(exc)) from exc
        return NdefProfile(records=records)

    def _read_data_file(self, *, file_no: int, offset: int, length: int) -> list[int]:
        """Read bytes from an NTAG 424 DNA data file."""
        offset_bytes = int_to_3bytes_le(offset)
        return self.client.send_checked(
            Ntag424ApduPreset.read_data_file(
                file_no=file_no,
                offset=offset_bytes,
                length=int_to_3bytes_le(length),
            ),
        )

    def _get_file_settings(self, file_no: int) -> list[int]:
        """Send GetFileSettings for an NTAG 424 DNA file."""
        return self.client.send_checked(Ntag424ApduPreset.get_file_settings(file_no))

    def _get_key_versions(self) -> list[int]:
        """Send GetKeyVersion for all NTAG 424 DNA application key slots."""
        return [
            self._get_key_version(key_no) for key_no in range(self.ntag424_key_slots)
        ]

    def _get_key_version(self, key_no: int) -> int:
        """Send GetKeyVersion for one NTAG 424 DNA application key."""
        data = self.client.send_checked(Ntag424ApduPreset.get_key_version(key_no))
        if len(data) != 1:
            msg = "NTAG 424 DNA key version response must be 1 byte"
            raise self.UnsupportedProfileReadError(msg)
        return data[0]

    def _read_type2_profile(self, uid: str) -> Ntag21xProfile:
        """Read an NTAG21x/Type 2 Tag profile through PC/SC binary reads."""
        capacity_bytes = self._read_type2_capacity_bytes()
        tag = self._build_type2_tag_info(uid=uid, capacity_bytes=capacity_bytes)
        memory = self._read_type2_ndef_memory(capacity_bytes)
        try:
            ndef = NdefProfileParser.parse_type2_memory(memory)
        except NdefProfileParser.NdefParseError as exc:
            raise self.NdefParseError(str(exc)) from exc
        return Ntag21xProfile(
            tag=tag,
            capacity_bytes=capacity_bytes,
            ndef=ndef,
        )

    def _read_type2_tag_info(self, uid: str) -> TagInfo:
        """Read Type 2 capability data and return detected tag metadata."""
        capacity_bytes = self._read_type2_capacity_bytes()
        return self._build_type2_tag_info(uid=uid, capacity_bytes=capacity_bytes)

    def _build_type2_tag_info(self, *, uid: str, capacity_bytes: int) -> TagInfo:
        """Build Type 2 tag metadata from already-read capability data."""
        return TagInfo(
            type=self._detect_type2_tag_type(capacity_bytes),
            uid=uid,
        )

    def _read_type2_capacity_bytes(self) -> int:
        """Read usable Type 2 Tag capacity from the capability container."""
        cc = self._read_type2_page(self.type2_cc_page)
        return cc[2] * 8

    def _detect_type2_tag_type(self, capacity_bytes: int) -> TagType:
        """Detect the NTAG21x product from the Type 2 capability container."""
        tag_type = self.type2_capacity_types.get(capacity_bytes)
        if tag_type is None:
            msg = f"Unsupported Type 2 Tag capacity: {capacity_bytes} bytes"
            raise self.UnsupportedProfileReadError(msg)
        return tag_type

    def _read_type2_page(self, page: int) -> list[int]:
        """Read one Type 2 Tag page using the PC/SC READ BINARY command."""
        data = self.client.send_checked(
            PcscContactlessApduPreset.read_binary(
                page=page,
                length=self.type2_page_size,
            ),
        )
        if len(data) != self.type2_page_size:
            msg = "Type 2 Tag page reads must return 4 bytes"
            raise self.NdefParseError(msg)
        return data

    def _read_type2_ndef_memory(self, capacity_bytes: int) -> list[int]:
        """Read the Type 2 Tag user memory area that contains NDEF TLVs."""
        page_count = (capacity_bytes + self.type2_page_size - 1) // self.type2_page_size
        memory: list[int] = []
        for page in range(
            self.type2_ndef_start_page,
            self.type2_ndef_start_page + page_count,
        ):
            memory.extend(self._read_type2_page(page))
            if self.type2_terminator_tlv in memory:
                break
        return memory[:capacity_bytes]

    @classmethod
    def create_pcsc_backend(cls, reader_name: str | None = None) -> PcscBackend:
        """Create a PC/SC backend adapter."""
        if reader_name is not None:
            return cls(reader=PcscReaderProvider.get(reader_name))

        readers = PcscReaderProvider.readers()
        if not readers:
            raise PcscReaderProvider.ReaderNotFoundError
        return cls(reader=readers[0])

    @staticmethod
    def pcsc_backend_names() -> list[str]:
        """Return available PC/SC reader backend names without the pcsc prefix."""
        return list(PcscReaderProvider.reader_names())
