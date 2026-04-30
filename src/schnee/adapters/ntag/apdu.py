from typing import Annotated, Literal

from pydantic import BaseModel, Field, model_validator

BYTE_MAX = 0xFF
SHORT_LE_MAX = 0x100
EXTENDED_LENGTH_MAX = 0x10000
Byte = Annotated[int, Field(ge=0, le=0xFF)]
APDUCaseType = Literal["case1", "case2", "case3", "case4"]


class CommandAPDU(BaseModel):
    """ISO/IEC 7816-4 command APDU."""

    cla: int = Field(description="Instruction class byte", ge=0, le=0xFF)
    ins: int = Field(description="Instruction byte", ge=0, le=0xFF)
    p1: int = Field(default=0, description="Parameter 1", ge=0, le=0xFF)
    p2: int = Field(default=0, description="Parameter 2", ge=0, le=0xFF)
    data: list[Byte] = Field(default_factory=list, description="Command data bytes")
    le: int | None = Field(
        default=None,
        description="Expected response length. None means Le is omitted.",
        ge=0,
        le=0x10000,
    )
    extended: bool = Field(
        default=False,
        description="Encode APDU using extended length fields",
    )

    class CommandAPDUError(Exception):
        """Base exception for CommandAPDU-specific failures."""

    class ShortDataLengthExceededError(CommandAPDUError):
        """Raised when short APDU data exceeds the maximum supported length."""

    class ShortLeLengthExceededError(CommandAPDUError):
        """Raised when short APDU Le exceeds the maximum supported length."""

    class ExtendedDataLengthExceededError(CommandAPDUError):
        """Raised when extended APDU data exceeds the maximum supported length."""

    class MissingLeError(CommandAPDUError):
        """Raised when Le is required for encoding but not set."""

    class MissingLengthValueError(CommandAPDUError):
        """Raised when a required APDU length field value is not set."""

    @model_validator(mode="after")
    def validate_apdu(self) -> CommandAPDU:
        """Validate length limits for the configured APDU."""
        if not self.extended and len(self.data) > BYTE_MAX:
            msg = "short APDU data length must be <= 255"
            raise self.ShortDataLengthExceededError(msg)

        if self.extended and len(self.data) > EXTENDED_LENGTH_MAX:
            msg = "extended APDU data length must be <= 65536"
            raise self.ExtendedDataLengthExceededError(msg)

        if not self.extended and self.le is not None and self.le > SHORT_LE_MAX:
            msg = "short APDU Le must be <= 256"
            raise self.ShortLeLengthExceededError(msg)

        return self

    @property
    def case(self) -> APDUCaseType:
        """Return the ISO/IEC 7816-4 APDU case derived from data and Le."""
        if not self.data and self.le is None:
            return "case1"
        if not self.data and self.le is not None:
            return "case2"
        if self.data and self.le is None:
            return "case3"
        return "case4"

    def to_list(self) -> list[int]:
        """Serialize the command APDU into a list of bytes."""
        header = [self.cla, self.ins, self.p1, self.p2]
        if self.extended:
            return self._to_extended_list(header)
        return self._to_short_list(header)

    @property
    def apdu(self) -> list[int]:
        """Return the serialized command APDU bytes."""
        return self.to_list()

    def _to_short_list(self, header: list[int]) -> list[int]:
        """Serialize the APDU using short length encoding."""
        out = [*header]

        if self.case == "case1":
            return out

        if self.case == "case2":
            return [*out, self._encode_short_le(self.le)]

        out += [len(self.data), *self.data]

        if self.case == "case4":
            out += [self._encode_short_le(self.le)]

        return out

    def _to_extended_list(self, header: list[int]) -> list[int]:
        """Serialize the APDU using extended length encoding."""
        out = [*header]

        if self.case == "case1":
            return out

        if self.case == "case2":
            return [*out, 0x00, *self._encode_u16_be_field(self.le)]

        out += [0x00, *self._encode_u16_be_field(len(self.data)), *self.data]

        if self.case == "case4":
            out += self._encode_u16_be_field(self.le)

        return out

    @classmethod
    def _encode_short_le(cls, le: int | None) -> int:
        """Encode Le for short APDUs, using `0x00` for maximum length."""
        if le is None:
            msg = "Le must be set"
            raise cls.MissingLeError(msg)
        return 0x00 if le in (0, 256) else le

    @classmethod
    def _encode_u16_be_field(cls, value: int | None) -> list[int]:
        """Encode a 16-bit APDU length field in big-endian byte order."""
        if value is None:
            msg = "length value must be set"
            raise cls.MissingLengthValueError(msg)
        encoded = 0x0000 if value in (0, 65536) else value
        return [(encoded >> 8) & 0xFF, encoded & 0xFF]


class ResponseAPDU(BaseModel):
    """ISO/IEC 7816-4 response APDU."""

    data: list[Byte] = Field(default_factory=list, description="Response data bytes")
    sw1: int = Field(description="Status byte 1", ge=0, le=0xFF)
    sw2: int = Field(description="Status byte 2", ge=0, le=0xFF)

    @property
    def status(self) -> int:
        """Return the combined two-byte status word."""
        return (self.sw1 << 8) | self.sw2

    @property
    def ok(self) -> bool:
        """Return whether the response indicates success."""
        return self.status in (0x9000, 0x9100)

    def to_list(self) -> list[int]:
        """Serialize the response APDU into payload bytes plus status word."""
        return [*self.data, self.sw1, self.sw2]
