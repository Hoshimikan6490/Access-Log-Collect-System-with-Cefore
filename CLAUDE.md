# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repository is

A fork of NICT's [Cefore](https://github.com/cefore/cefore) 0.12.x (CCNx-1.0 / RFC8569, RFC8609 ICN platform, written in C) extended with an **access-log tagging** feature: routers stamp forwarded Interests with a router identifier ("log tag"), and that tag is carried back on the returning Data packet so access logs can be collected along the path. Upstream docs live in [doc/](doc/) (Configuration.md, Daemon.md, Tools.md). Commit messages in this repo are written in Japanese.

## Build

Linux/macOS only (POSIX sockets, autotools). It does not build natively on Windows; use a Linux machine/VM.

```sh
autoconf && automake
./configure --enable-cache --enable-debug   # also: --enable-csmgr, --with-openssl-dir=...
make
sudo make install && sudo ldconfig
```

- [build.sh](build.sh) does dependency install + the above with `--enable-cache --enable-debug`.
- [cleanup.sh](cleanup.sh) stops daemons, removes installed binaries/libs under `$CEFORE_DIR` (default `/usr/local`), clears `/tmp/cef_*` sockets and runs `make distclean`. It keeps `$CEFORE_DIR/cefore/*.conf`.
- `make install` only copies config files (e.g. `cefnetd.conf`, `log_tag.yaml`) into `$CEFORE_DIR/cefore/` if they don't already exist, so changes to `*.def` templates won't overwrite an installed config.
- Generated `Makefile.in` files are committed. When editing a `Makefile.am`, update the matching `Makefile.in` too (or regenerate with automake).

There is no automated test suite.

## Build and verification

- The user performs builds and runtime tests. Review whether code follows the language's syntax and formatting rules, and reason through the processing logic to assess whether it is theoretically correct.
- Runtime checks may include `cefnetdstart`, `cefstatus`, and tools like `cefputfile` / `cefgetfile` between nodes; the user runs them.

## Shell and file operations

- Within this workspace, you may use the shell to retrieve or edit text in code and document files without asking the user first.
- Explain clearly to the user what you changed.
- Never delete files. Ask the user to perform any file deletion.
- Ask the user before using the shell for operations other than retrieving or editing files or data, including running applications.

## Language

- Maintain code and documents in English.
- Communicate with the user in Japanese.

## Architecture overview

- `src/lib/` → `libcefore`: shared code used by the daemons and tools. Key files: `cef_frame.c` (CCNx TLV parse/build, including optional-header parsing), `cef_pit.c` / `cef_fib.c`, `cef_face.c`, `cef_client.c` (config dir lookup, time).
- `src/cefnetd/`: the forwarding daemon.
  - `cef_netd.c`: handle creation, `cefnetd_config_read` (parses `cefnetd.conf` line by line through `cefnetd_trim_line_string`, which strips all whitespace and does **not** strip quotes), event loop, and the `cefnetd_incoming_*_process` handlers for Interest, ContentObject, ccninfo and so on.
  - `cef_sched.c`: `cefnetd_interest_forward` and other packet-forwarding helpers.
  - `cef_netd.h`: `CefT_Netd_Handle`, the central state struct that is passed everywhere.
- `src/csmgrd/`, `src/conpubd/`: content-store manager and content publisher daemons. `src/plugin/`, `src/dlplugin/`: transport and forwarding-strategy plugins.
- `tools/`, `utils/`: CLI tools (`cefgetfile`, `ccninfo`, ...) and the start/stop/status shell wrappers.
- `config/*.def`: config templates installed as `$CEFORE_DIR/cefore/*`. Parameter-name macros (`CefC_ParamName_*`) are defined in `src/include/cefore/cef_define.h`.

## Access-log tagging (this fork's feature)

The flow spans several files:

1. **Config.** `cefnetd.conf` has `ENABLE_ACCESS_LOG` (0/1) and `LOG_TAG_NAME`. If `LOG_TAG_NAME` is empty, `cefnetd_handle_create` falls back to `My_Node_Name`. `My_Node_Name` comes from `NODE_NAME`, or from the node IP address when `NODE_NAME` is unset. Separately, `config/log_tag.yaml` lists content names (`contents: - name: / producer:`). It is read by `cefnetd_log_tag_config_read` into `hdl->log_tag_contents`.
2. **Interest forwarding.** When access logging is enabled, `cefnetd_interest_forward` calls `cefnetd_packet_add_log_tag` (in `cef_sched.c`), which adds a `CefC_T_LOG_TAG` TLV inside the NICT vendor `CefC_T_OPT_ORG` hop-by-hop header (PEN `CefC_NICT_PEN`). This function rewrites `header_len` / `payload_len` in place.
3. **Parse & PIT.** `cef_frame_opheader_user_tlv_parse` stores the tag in `CefT_CcnMsg_OptHdr.log_tag`. When the PIT entry is created, `cef_pit_entry_lookup_with_lock` copies it into `CefT_Pit_Entry.log_tag`.
4. **Data return.** In the ContentObject path in `cef_netd.c`, if the object came from a neighbor and its name has `producer: true` in `log_tag.yaml` (`cefnetd_log_tag_is_enabled`), the stored PIT tag is added to the outgoing Data. Tagging cache-served responses (csmgr/local cache) is intentionally not implemented yet.

When adding a new field to a packet, update the TLV type in `cef_frame.h`, the parse in `cef_frame.c`, any PIT storage in `cef_pit.h` / `cef_pit.c`, and the length fix-ups wherever the packet is rebuilt.
