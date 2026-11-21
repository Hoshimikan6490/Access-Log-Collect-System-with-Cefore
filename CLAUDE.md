# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this repository is

A fork of NICT's [Cefore](https://github.com/cefore/cefore) 0.12.x (CCNx-1.0 ICN platform, C) with an **access-log tagging** feature: routers stamp forwarded Interests with a router identifier ("log tag"), the tag is carried back on the returning Data, and the router next to the Consumer records the access. Upstream docs: [doc/](doc/). Commit messages are written in Japanese.

## Rules

- Do not build or test; the user does that.
- You may read and edit text files in this workspace via the shell without asking. Ask before any other shell use (running applications, etc.).
- Never delete files; ask the user.
- Code and documents in English; talk to the user in Japanese.
- Keep changes in scope: do not add fields, params or APIs unrelated to the task. Do not keep unused code (the transfer side below is the only planned exception).
- Explain clearly what you changed.

## Layout

- `src/lib/`: `libcefore` (`cef_frame.c` TLV parse/build, `cef_pit.c`, `cef_fib.c`, `cef_face.c`, `cef_client.c`).
- `src/cefnetd/`: forwarding daemon. `cef_netd.c` (handle, `cefnetd_config_read`, event loop, `cefnetd_incoming_*_process`), `cef_sched.c` (forwarding helpers, tag add/remove), `cef_netd.h` (`CefT_Netd_Handle`), `cef_access_log.c/.h`.
- `src/csmgrd/`, `src/conpubd/`, `src/plugin/`, `src/dlplugin/`, `tools/`, `utils/`: other daemons, plugins, CLI tools.
- `config/*.def`: config templates. `CefC_ParamName_*` macros are in `src/include/cefore/cef_define.h`.
- `cefnetd_config_read` trims all whitespace and does **not** strip quotes.

## Access-log tagging

1. **Config.** `cefnetd.conf`: `ENABLE_ACCESS_LOG`, `LOG_TAG_NAME` (empty → `My_Node_Name`, i.e. `NODE_NAME` or the node IP; max `CefC_Max_Log_Tag_Size` = 20 bytes). `config/log_tag.yaml` (`name:` / `collect:`) is read at start-up into `hdl->log_tag_contents`. A `name` must start with `ccnx:/` and fit in the buffer, otherwise the entry is ignored with a warning; a trailing `/*` is a prefix wildcard.
2. **Interest.** `cefnetd_interest_forward` calls `cefnetd_packet_add_log_tag` (`cef_sched.c`): a `CefC_T_LOG_TAG` TLV inside the NICT `CefC_T_OPT_ORG` header (PEN `CefC_NICT_PEN`). An existing tag is never overwritten (`overwrite = 0`).
3. **Parse & PIT.** `cef_frame_opheader_user_tlv_parse` fills `CefT_CcnMsg_OptHdr.log_tag`; a tag longer than 20 bytes is treated as no tag (`log_tag_len = 0`, never truncated; the TLV itself stays in the packet). `cef_pit_entry_down_face_update` keeps the first tag per downstream Face (`CefT_Down_Faces.log_tag`).
4. **Data.** The ContentObject path in `cef_netd.c` uses `cefnetd_log_tag_lookup` (exact name beats wildcard; `collect: true` beats `false` on a tie; results are cached per Name) to pick the role. Only the Producer is assumed to have `log_tag.yaml`:
   - `collect: true` → tag per Face, replacing any tag (`cefnetd_object_forward_with_log_tag`, `overwrite = 1`).
   - `collect: false` → strip any LOG_TAG TLV, including an empty one (`cefnetd_object_forward_without_log_tag`).
   - no match (router / network cache) → re-tag per Face only if the Data has a usable tag (`log_tag_len > 0`); otherwise take the strip path, so an empty or oversized (misconfigured) tag is removed and the Data is forwarded as plain ICN without an access record. A Data with no TLV is forwarded as it is. An oversized tag on an Interest is left untouched (plain forwarding).
   - Tag per Face: the Interest's own tag from the PIT; if that Interest had none (Consumer directly below), this router's `log_tag_name`, never another Interest's tag.
5. **Access log buffer** (`cef_access_log.c/.h`, only when `ENABLE_ACCESS_LOG=1`). `cefnetd_access_log_record` records a Face only if its Data really carries this router's own tag (`tagged_ok[]` from the forward function; tag building can fail and fall back to the original msg). Entries are aggregated per (Face-ID, Name without chunk) with `first_ts`/`last_ts`/`access_count` (chunk 0 only, or every Data if no chunk)/`chunk_count`. Fixed-size slots + hash + LRU: when full the oldest entry is overwritten (`evicted`); a Name over `ACCESS_LOG_NAME_MAX` is skipped (`skipped_long_name`), never truncated. Two buffers swap at `ACCESS_LOG_SWAP_THRESHOLD`. Params: `ACCESS_LOG_BUFFER_SIZE`, `ACCESS_LOG_NAME_MAX`, `ACCESS_LOG_SWAP_THRESHOLD`. `BUFFER_SIZE * NAME_MAX` is capped at `CefC_AccessLog_Max_NameMem` (64 MiB per buffer); `cefnetd_handle_create` fails to start above it and logs the allocated size otherwise. Keep `config/cefnetd.conf.def` and `doc/Configuration.md` in sync when changing these.
   - **Known limitation:** entries are keyed by Face-ID, which is reused after a Face closes, so a new peer on a reused Face-ID can merge into the old peer's entry. Not fixed yet; decide together with the transfer design (candidate: a per-Face generation number stored in `CefT_Face` and added to the entry key).
   - **Transfer side is not implemented.** `cef_access_log_acquire` / `_release` have no callers, so after the first swap the other buffer stays READY and no further swap happens (the accumulation buffer only evicts). Do not add `flush` or similar helpers until the transfer design exists.

## Invariants for packet rewriting

- `cefnetd_packet_add_log_tag` / `_remove_log_tag` require `pkt_len == header_len + payload_len` and size limits; on failure add returns 0 and logs a warning for a length mismatch (caller keeps the original msg, i.e. forwards untagged), remove returns -1 (the Data is dropped: fail-closed by design, so a tagged Data is never forwarded when the tag cannot be removed).
- Rebuilt packets go into `hdl->log_tag_buf`, never into the receive buffer or a cache entry; re-parse with `cefnetd_packet_reparse`.
- Adding a packet field: update the TLV type in `cef_frame.h`, the parse in `cef_frame.c`, PIT storage in `cef_pit.h/.c`, and every length fix-up where the packet is rebuilt.
