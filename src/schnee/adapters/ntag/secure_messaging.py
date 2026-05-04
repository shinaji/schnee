from typing import Literal

from pydantic import BaseModel, Field

from schnee.adapters.ntag.apdu import Byte  # noqa: TC001
from schnee.adapters.ntag.crypt import aes_cbc_encrypt_for_ev2, calculate_ev2_mac

CommunicationModeType = Literal["plain", "mac", "full"]


class EV2SessionContext(BaseModel):
    """Session values required by NTAG424 EV2 secure messaging."""

    cmd_ctr: int = Field(ge=0, le=0xFFFF)
    ti: bytes = Field(min_length=4, max_length=4)
    session_key_mac: bytes = Field(min_length=16, max_length=16)
    session_key_enc: bytes = Field(min_length=16, max_length=16)


class NTAG424CommandSpec(BaseModel):
    """NTAG424 command payload description before APDU wrapping."""

    cmd_code: int = Field(ge=0, le=0xFF)
    file_no: int | None = Field(default=None, ge=0, le=0xFF)
    header_data: list[Byte] = Field(
        default_factory=list,
        description="Command bytes that stay outside encrypted payload",
    )
    command_data: list[Byte] = Field(
        default_factory=list,
        description="Command bytes that may be encrypted",
    )
    mode: CommunicationModeType = Field(default="plain")


class NTAG424SecureMessaging:
    """Build NTAG424 EV2 command payloads before APDU wrapping."""

    @classmethod
    def build_payload(
        cls,
        spec: NTAG424CommandSpec,
        ctx: EV2SessionContext | None = None,
    ) -> list[int]:
        """Build a plain, MACed, or encrypted NTAG424 EV2 command payload."""
        if spec.mode == "plain":
            return [*spec.header_data, *spec.command_data]

        if ctx is None:
            msg = "Secure messaging requires EV2SessionContext"
            raise ValueError(msg)

        file_no_bytes = b"" if spec.file_no is None else bytes([spec.file_no])

        if spec.mode == "mac":
            body = [*spec.header_data, *spec.command_data]
            mac = calculate_ev2_mac(
                session_key_mac=ctx.session_key_mac,
                cmd_code=spec.cmd_code,
                cmd_ctr=ctx.cmd_ctr,
                tran_id=ctx.ti,
                file_no=file_no_bytes,
                data=bytes(body),
            )
            return [*body, *list(mac)]

        encrypted_payload = cls._encrypt_command_data(
            command_data=spec.command_data,
            ctx=ctx,
        )
        body = [*spec.header_data, *encrypted_payload]
        mac = calculate_ev2_mac(
            session_key_mac=ctx.session_key_mac,
            cmd_code=spec.cmd_code,
            cmd_ctr=ctx.cmd_ctr,
            tran_id=ctx.ti,
            file_no=file_no_bytes,
            data=bytes(body),
        )
        return [*body, *list(mac)]

    @staticmethod
    def _encrypt_command_data(
        command_data: list[int],
        ctx: EV2SessionContext,
    ) -> list[int]:
        """Encrypt command data using the EV2 session ENC key and derived IV."""
        iv_input = bytes(
            [
                0xA5,
                0x5A,
                *ctx.ti,
                *ctx.cmd_ctr.to_bytes(2, byteorder="little"),
                *bytes(8),
            ],
        )
        iv = aes_cbc_encrypt_for_ev2(
            session_key_enc=ctx.session_key_enc,
            iv=None,
            plain_data=iv_input,
        )
        encrypted_payload = aes_cbc_encrypt_for_ev2(
            session_key_enc=ctx.session_key_enc,
            iv=iv,
            plain_data=bytes(command_data),
        )
        return list(encrypted_payload)
