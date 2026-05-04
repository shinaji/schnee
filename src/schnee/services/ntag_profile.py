"""Services for NTAG profile operations."""

import sys

from pydantic import ConfigDict

from schnee.adapters.backend import PcscBackend
from schnee.adapters.backend.core import Backend
from schnee.adapters.ntag.profile import NtagProfile
from schnee.services.base import Service


class ReadNtagProfileService(Service[NtagProfile]):
    """Read the current profile from an NTAG profile backend."""

    class Request(Service.Request):
        """Request for reading an NTAG profile."""

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    def process(self) -> NtagProfile:
        """Read the current NTAG profile."""
        backend = Backend.get(name="pcsc")
        profile = backend.read_profile()
        print(profile)
        return profile


def main() -> int:
    """Run the profile read service from the command line."""
    try:
        ReadNtagProfileService.call(ReadNtagProfileService.Request())
    except PcscBackend.UnsupportedProfileReadError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
