# schnee

`schnee` is a Python package and CLI for working with NFC/RFID tags through a PC/SC
reader, with a current focus on NTAG profile inspection and NDEF URL writes.

## Installation

Install the package from PyPI:

```bash
pip install schnee
```

## Requirements

`schnee` talks to tags through PC/SC via `pyscard`, so practical use requires:

- a compatible NFC or smart card reader
- a working system PC/SC library/service
- access to the target tag

Platform-specific PC/SC prerequisites:

- **Linux**: install a PC/SC implementation such as `pcsc-lite` and ensure the
  `pcscd` daemon/service is installed and running. Depending on your
  distribution, you may also need your reader's driver package.
- **Windows**: `pyscard` uses the built-in WinSCard PC/SC subsystem that ships
  with Windows; make sure the smart card service and your reader driver are
  available.
- **macOS**: `pyscard` uses the system `PCSC.framework`, which is included with
  macOS; make sure the reader is connected and recognized by the system.

If the PC/SC stack, service, or reader is not available, `pyscard` may fail to
import, no readers may be discovered, or CLI commands that access hardware will
fail during reader discovery or card communication.

## CLI Usage

After installation, the `schnee` command is available on your `PATH`.

Show the top-level help:

```bash
schnee --help
```

List selectable backends and detected PC/SC readers:

```bash
schnee backends
```

Read the current NTAG profile as JSON:

```bash
schnee ntag read --backend pcsc
```

Use a specific reader by name:

```bash
schnee ntag read --backend "pcsc:ACS ACR1252 1S CL Reader PICC 0"
```

Write a URL as a single NDEF URI record:

```bash
schnee ntag write-url --backend pcsc --url "https://example.com"
```

For NTAG 424 DNA tags that require application authentication before writing,
provide the current 16-byte AES key as 32 hex characters:

```bash
schnee ntag write-url \
  --backend pcsc \
  --url "https://example.com" \
  --ntag424-master-key-hex 00112233445566778899aabbccddeeff
```

**Warning:** passing a secret key on the command line can expose it through
shell history, terminal logging, or process listings visible to other local
users. Avoid using real production keys this way; prefer a safer secret input
mechanism if one is available in your environment.

Verify an NTAG 424 DNA SDM MAC from mirrored URL data:

```bash
schnee ntag verify-sdm-mac \
  --signed-text "example.com/t?uid=044C2F82322190&ctr=250000&mac=" \
  --mac 260d8310beb0e062 \
  --sdm-key-hex 00112233445566778899aabbccddeeff \
  --uid 044C2F82322190 \
  --counter 250000
```

When the tag stored the URI record without NDEF URI compression, keep the
default `--ndef-prefix no_prefix` and pass `--signed-text` exactly as it was
mirrored.

When the tag stored the URI record with an NDEF URI Identifier Code such as
`https://`, pass that code through `--ndef-prefix`. The verifier removes the
expanded prefix from `signed_text` before MAC calculation only when both of the
following are true:

- the selected `--ndef-prefix` expands to a non-empty prefix such as
  `https://`
- `--signed-text` starts with that expanded prefix

This means `signed_text` may include the display prefix copied from the tag
scan, or it may already be prefix-normalized. Both are accepted as long as
`--ndef-prefix` matches the URI Identifier Code used when the URL was stored.

For a tag that used compressed `https://` storage, these two commands verify
the same signed bytes:

```bash
schnee ntag verify-sdm-mac \
  --signed-text "https://example.com/t?uid=044C2F82322190&ctr=250000&mac=" \
  --mac 260d8310beb0e062 \
  --sdm-key-hex 00112233445566778899aabbccddeeff \
  --uid 044C2F82322190 \
  --counter 250000 \
  --ndef-prefix https
```

```bash
schnee ntag verify-sdm-mac \
  --signed-text "example.com/t?uid=044C2F82322190&ctr=250000&mac=" \
  --mac 260d8310beb0e062 \
  --sdm-key-hex 00112233445566778899aabbccddeeff \
  --uid 044C2F82322190 \
  --counter 250000 \
  --ndef-prefix https
```

If you provide `--uid` or `--counter`, those bytes must match the tag's SDM
configuration and the mirrored URL contents. In particular, `--counter` expects
the 3 mirrored bytes in URL order, and the verifier handles the NTAG 424 DNA
counter byte-order conversion internally.

## Python API

The stable Python entry points currently exposed by the package are the service
classes re-exported from `schnee.services`. For example, you can list the
selectable backends from Python:

```python
from schnee.services import ListBackendNamesService

backends = ListBackendNamesService.call(ListBackendNamesService.Request())
print(backends)
```

This call uses the same backend discovery as `schnee backends`, so it also
depends on a working PC/SC environment when the PC/SC backend is enabled.

## Trademarks and Disclaimer

* **Trademarks**:
  NTAG, MIFARE, and NXP are registered trademarks of NXP B.V. This project is an independent open-source implementation
  and is not affiliated with, endorsed by, or sponsored by NXP B.V.
* **Accuracy of Information**:
  This SDK is developed based on publicly available datasheets. While every effort has been made to ensure the accuracy
  of the implementation, the author makes no guarantees regarding its suitability for any specific purpose.
* **Limitation of Liability**:
  In no event shall the author be liable for any damages arising from the use of this software, including but not
  limited to hardware damage (NFC tags, readers, etc.), data loss, or "bricking" of tags due to incorrect AES key
  configuration or authentication failures. Use this software at your own risk.
