# Security backports ledger — russh 0.44 fork (Connexa)

next review: 2026-11-30

This fork (`theridler1/russh-fork-044`) is russh 0.44.1 plus the
`sntrup761x25519-sha512@openssh.com` KEX. It is a path dependency of Connexa,
so `cargo-deny` and `cargo-audit` cannot match upstream russh advisories
against it. This ledger is the replacement: Connexa's
`src-tauri/tests/ci_policy.rs::fork_advisory_ledger_is_current` requires the
rows below and fails once the `next review` date above has passed.

The fork is a stopgap (roadmap D2). It is removed by BE-4 (v1.16), which
rebases Connexa onto a current upstream russh; every `accepted-until-BE-4`
row is closed by that rebase.

Connexa only runs the russh **client** (and the agent **client**). Server-only
advisories are therefore listed for completeness.

Status values: `fixed-in-0.44.1` · `backported <sha>` · `not-reachable (why)` ·
`accepted-until-BE-4`. SHAs are commits on this fork's `master`. Titles are
from the GitHub advisory database (checked 2026-10-12).

| Id | Title | Affected path in 0.44 | Status | Evidence |
|---|---|---|---|---|
| RUSTSEC-2026-0154 / CVE-2026-46673 / GHSA-g9f8-wqj9-fjw5 | Unbounded 32-bit allocation (agent frame length) | `russh-keys/src/agent/client.rs` `read_response`, `russh-keys/src/agent/server.rs` read loop | backported 8b43370 | `agent::client::tests::client_rejects_oversized_frame`, `client_accepts_frame_at_limit`, `client_rejects_zero_length_frame`, `agent::server::tests::server_rejects_oversized_frame` |
| CVE-2026-102824 / GHSA-w3jg-pjxf-73p4 | Missing X25519 zero-point validation in hybrid ML-KEM key exchange | bug class: the X25519 half of `russh/src/kex/hybrid_sntrup761.rs` and `russh/src/kex/curve25519.rs` (the fork has no ML-KEM) | backported c7632f8 (bug class) | `kex::hybrid_sntrup761::tests::rejects_zero_x25519_in_server_reply`, `rejects_zero_x25519_in_client_init`, `rejects_low_order_x25519_both_directions`, `kex::curve25519::tests::rejects_low_order_points` |
| GHSA-g9hv-x236-4qp3 / CVE-2026-73429 | Client wrong-length X25519 `clone_from_slice` panic (pre-auth DoS) | `russh/src/kex/curve25519.rs` `compute_shared_secret` | backported c7632f8 | `kex::curve25519::tests::rejects_wrong_length_share`, `kex::hybrid_sntrup761::tests::truncated_client_init_does_not_panic` |
| GHSA-5xvq-cp9x-6p6r / CVE-2026-73430 | Pre-auth remote panic via all-zero Curve25519 peer public value (`encode_mpint` OOB) | `russh-keys/src/encoding.rs` `extend_ssh_mpint` / `mpint_len`, reached from `curve25519.rs` `compute_exchange_hash` (client and server) | backported c7632f8 + e00ec3f | the all-zero secret is rejected before hashing (`rejects_low_order_points`); `encoding::tests::mpint_of_zero_is_empty_and_does_not_panic` |
| CVE-2026-48107 / GHSA-g9g7-5cgw-6v28 | Unchecked keyboard-interactive prompt count in client auth | `russh/src/client/encrypted.rs` USERAUTH_INFO_REQUEST parsing | backported 603a115 | `client::encrypted::tests::info_request_rejects_huge_prompt_count`, `info_request_parses_two_prompts`, `info_request_rejects_truncated_prompts` |
| CVE-2024-43410 / GHSA-vgvv-x7xg-6cqg | OOM denial of service due to allocation of untrusted amount (packet length) | `russh/src/cipher/mod.rs` | fixed-in-0.44.1 | `MAXIMUM_PACKET_LEN` check in `cipher/mod.rs` (upstream fix shipped in the 0.44.1 base) |
| CVE-2026-46702 / GHSA-wwx6-x28x-8259 | Post-decompression SSH packet size unbounded | `russh/src/compression.rs` (zlib) | not-reachable (Connexa pins compression to `none` in both clients) | Connexa `unit_tests.rs::russh_clients_pin_compression_to_none` |
| CVE-2026-46705 / GHSA-hpv4-5h6f-wqr3 | Server userauth state not reset when the authentication principal changes | `russh/src/server/encrypted.rs` | not-reachable (server path only; Connexa never runs a russh server) | no `russh::server` use in Connexa |
| CVE-2026-102823 / GHSA-47hw-gvq5-r2gm | Client-side channel-scoped Handler callbacks fire for channel IDs the client never opened | `russh/src/client/encrypted.rs` channel message dispatch | accepted-until-BE-4 | reachable post-auth from a hostile server (the host key has been verified by then); impact is spurious callbacks on unopened ids, not memory corruption. Fixed upstream in 0.63.1 |
| CVE-2026-48110 / GHSA-4r3c-5hpg-58qr | SSH message fields decoded through allocation-first parsers | `russh-keys/src/encoding.rs` readers and their callers | accepted-until-BE-4 | the packet itself is bounded by `MAXIMUM_PACKET_LEN` (256 KiB), which bounds any field allocation; the pre-auth abort cases (prompt count, agent frame) are backported above |
| CVE-2026-102821 / GHSA-35g8-35p8-c8fw | Unbounded memory exhaustion via CHANNEL_OPEN flood during a client-stalled rekey | `russh/src/server/` | accepted-until-BE-4 | server path only; not reachable from Connexa's client |
| CVE-2026-102822 / GHSA-p8qx-h547-fjw9 | Negotiating a MAC-requiring block cipher (CTR/CBC) with mac=none panics | `russh/src/cipher/` | accepted-until-BE-4 | Connexa's client never offers `none` as a MAC (the default MAC list is HMAC only) |
| CVE-2026-102825 / GHSA-g6xm-f9xp-qq35 | Configured server auth-attempt cap not enforced in the USERAUTH_REQUEST path | `russh/src/server/encrypted.rs` | accepted-until-BE-4 | server path only; not reachable from Connexa's client |
| GHSA-cqjc-rmpq-xprq / CVE-2026-73489 | Post-auth remote panic via pty-req with more than 130 terminal-mode records | `russh/src/server/encrypted.rs` | accepted-until-BE-4 | server path only; not reachable from Connexa's client |
| CVE-2026-68930 / GHSA-m65r-rprj-r5rg | Channel-scoped server callbacks reachable without an open channel | `russh/src/server/encrypted.rs` | not-reachable (server path only) | no `russh::server` use in Connexa |
| CVE-2026-42189 / GHSA-f5v4-2wr6-hqmg | Pre-auth DoS via unbounded allocation in the keyboard-interactive handler | `russh/src/server/` | not-reachable (server path only) | client side covered by the CVE-2026-48107 row |
| CVE-2026-48108 / GHSA-76r6-x97p-67vr | SSH identification parsing accepted non-canonical banners | `russh/src/ssh_read.rs` `read_ssh_id` | accepted-until-BE-4 | parsing is bounded (no allocation from peer lengths); impact is protocol strictness, not a crash |
| CVE-2026-102820 / GHSA-g4mp-vgx3-xrvm | Pageant `MemoryMap::read` out-of-bounds read / oversized allocation | `pageant` crate | not-reachable (0.44 has no Pageant support; Connexa uses the OpenSSH agent pipe or `SSH_AUTH_SOCK`) | no `pageant` code in the fork |
| CVE-2025-54804 / GHSA-h5rc-j5f5-3gcm | Missing overflow checks during channel window adjust | `russh/src/client/encrypted.rs` `recipient_window_size += amount` | accepted-until-BE-4 | post-auth; release builds wrap (no panic) and the window only affects flow control |
| CVE-2023-48795 / GHSA-45x7-px36-x8w8 | Terrapin prefix truncation | `russh/src/negotiation.rs` | fixed-in-0.44.1 | strict KEX (`kex-strict-*-v00@openssh.com`) is in the 0.44 base |
| CVE-2023-28113 / GHSA-cqvm-j2r2-hwpg | May use insecure Diffie-Hellman keys | `russh/src/kex/dh/` | fixed-in-0.44.1 | DH public value validation is in the 0.44 base (fixed upstream in 0.37.1) |
