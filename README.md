# NTCIP 1203 Agent

A self-contained, pure-Python simulator of a single Dynamic Message Sign
(DMS) compliant with [NTCIP 1203](artifacts/1203v0305a.mib). It speaks
SNMPv1 over UDP or TCP and is intended for exercising DMS-related features
of an Advanced Transportation Management System (ATMS) without needing a
real sign.

The agent implements:

- The MIB-II `system` group (`1.3.6.1.2.1.1`).
- The NTCIP 1203 `dms` object tree (`1.3.6.1.4.1.1206.4.2.3`): scalar
  status/configuration objects, `dmsMessageTable`, `dmsFontTable` /
  `dmsFontCharacterTable`, and `dmsGraphicTable`.
- `GetRequest`, `GetNextRequest`, and `SetRequest`, including the
  `dmsActivateMessage` activation state machine (put a message on the sign,
  blank the sign) and the `dmsMessageStatus` modify/validate state machine
  (with `dmsMessageCRC` computation).

It requires only the Python 3.7+ standard library to run.

## Requirements

- Python 3.7 or later (developed and tested against `py -3` / Python 3.13).
- `black` is only needed for re-formatting source (`pip install black`); it
  is not required to run the agent.

## Running the agent

From the repository root:

```
py -3 -m ntcip_agent
```

By default this listens on UDP `0.0.0.0:161` with read/write community
`public`, and presents a sign matching `artifacts/config_screenshot.jpg`
(FullMatrix, LED, 27x145 pixels, 24-bit color, 20 graphics, font management
enabled).

Note that port 161 is the standard SNMP port and typically requires
administrator/root privileges to bind. For local testing, copy
`config.example.json` and change `network.port` to an unprivileged port
(e.g. `16161`):

```
py -3 -m ntcip_agent --config my_config.json
```

```
py -3 -m ntcip_agent --config my_config.json -v   # -v / --verbose for debug logging
```

### Configuration file

`config.example.json` documents all available settings:

```json
{
  "network": {
    "host": "0.0.0.0",
    "port": 161,
    "transport": "udp",
    "read_community": "public",
    "write_community": "public"
  },
  "sign": {
    "sign_type": "vmsFull",
    "sign_technology": ["other", "led"],
    "sign_height_pixels": 27,
    "sign_width_pixels": 145,
    "color_scheme": "color24bit",
    "max_graphics": 20,
    "font_management_enabled": true
  }
}
```

- `network.transport` is `"udp"` or `"tcp"`.
- `network.read_community` / `network.write_community` are the SNMP
  community strings checked on `Get*Request` / `SetRequest` respectively.
- `sign.*` controls the values reported for `dmsSignType`,
  `dmsSignTechnology`, `vmsSignHeightPixels`, `vmsSignWidthPixels`,
  `dmsColorScheme`, and `dmsMaxNumberOfGraphics`.

## Testing the agent

A development SNMP client is provided at `tools/snmp_client.py` (it is a
standalone test tool, not part of the `ntcip_agent` package). With the agent
running (e.g. on port 16161 as configured above), in another terminal:

### 1. Poll the sign for status

```
py -3 -m tools.snmp_client --port 16161 poll
```

Prints `sysDescr`, `sysUpTime`, error/power/temperature status, control
mode, sign type/technology/dimensions/color scheme, font info, and message
activation status.

### 2. Put a message on the sign

```
py -3 -m tools.snmp_client --port 16161 put-message "[fo220]HELLO WORLD"
```

This runs the full `dmsMessageTable` lifecycle for a changeable message slot
(`modifyReq` -> write `dmsMessageMultiString` -> `validateReq` -> read back
the computed `dmsMessageCRC`) and then activates it via
`dmsActivateMessage`, reporting `dmsActivateMsgError` (expect `2` = `none`).

Useful options: `--slot N` (changeable message slot, default 1), `--owner`,
`--beacon {0,1}`, `--pixel-service {0,1}`, `--duration`, `--priority`.

### 3. Blank the sign

```
py -3 -m tools.snmp_client --port 16161 blank
```

Activates the `blank` message memory type via `dmsActivateMessage` and
reports `dmsActivateMsgError` (expect `2` = `none`).

### 4. Walk the font table

```
py -3 -m tools.snmp_client --port 16161 walk-font 20
```

Dumps the `fontEntry` row and every populated `characterEntry` row (number,
width, bitmap) for font index 20 (`FDOTColorDMS`, `fontNumber` 220, the
sign's default font).

### Other client commands

```
py -3 -m tools.snmp_client --port 16161 get 1.3.6.1.2.1.1.1.0
py -3 -m tools.snmp_client --port 16161 get-next 1.3.6.1.2.1.1
py -3 -m tools.snmp_client --port 16161 set 1.3.6.1.2.1.1.6.0 octet-string "Booth 12"
py -3 -m tools.snmp_client --port 16161 walk 1.3.6.1.4.1.1206.4.2.3.5
```

Add `--transport tcp` to talk to an agent configured for TCP. Run
`py -3 -m tools.snmp_client --help` (or `<subcommand> --help`) for full
usage.

## Running the test suite

```
py -3 -m unittest discover -s tests -v
```

This covers the BER/SNMP codec, the `dmsMessageCRC` algorithm, the
`dmsMessageTable`/`dmsActivateMessage` state machine, the MIB object
registry, the SNMP request handlers (`Get`/`GetNext`/`Set`, including error
cases), and a byte-exact replay of the captured SNMP sessions in
`artifacts/hex_dump_1.txt` (poll / put-message / blank) and
`artifacts/hex_dump_2.txt` (font table download).

## Source formatting

Source is formatted with [black](https://black.readthedocs.io/):

```
py -3 -m black ntcip_agent tests tools
```

## Project layout

```
ntcip_agent/        the agent package (BER codec, SNMP message codec, MIB
                     registry, sign state, server, CLI entrypoint)
ntcip_agent/data/    seed data: scalar object defaults and the font 220
                     (FDOTColorDMS) character set
tools/snmp_client.py development/test SNMP client (not part of the package)
tests/               unit tests, run via `python -m unittest discover -s tests`
config.example.json  example configuration file
artifacts/           reference materials: the NTCIP 1203 MIB, captured
                     hex dumps used to validate protocol behavior, and the
                     scripts used to derive the seed data in ntcip_agent/data
```
