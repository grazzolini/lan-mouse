# Lan Mouse Custom Stack

Snapshot: 2026-10-08. This package applies the residual custom stack to upstream
`f1b96bdcc0294d285bc9050b7e146800a3ef8796` (`v0.11.0-37-gf1b96bdcc0`).
The previous package used `392af44cbe06a7a591db86856ad6ed2aa83958d8`; the refresh
includes 23 additional upstream commits.

## Build

Check out `feat/pr-stack-build` from the
[grazzolini/lan-mouse fork](https://github.com/grazzolini/lan-mouse).
Keep `PKGBUILD` and `pr-stack-on-f1b96bd.patch` together, then run `makepkg -si`
from this directory on Arch Linux. `PKGBUILD` fetches the fork at the pinned
upstream commit, then applies the local patch. The package version is fixed to
this snapshot and does not depend on release tags being present in the fork.
The patch has a SHA-256 checksum in `PKGBUILD`. This is a local package recipe,
not an AUR publication.

Reconnect recovery update: 2026-10-09 (`pkgrel=2`). Outgoing connections retire
their receive and heartbeat operations even if DTLS shutdown fails. Each local
listener now retires its accepted connections before an interface or port is
rebound, preserving other listeners and releasing disconnected emulation handles.

Verification for this update: the patch applies to a clean pinned source archive
and reproduces the stack source exactly. On macOS, all 43 workspace tests,
formatting and strict workspace all-feature Clippy passed. Tests include repeated
live DTLS reconnect/rebind cycles, failed or hanging shutdown, and stale-session
isolation. The Linux package build and actual Sway suspend/resume with
bidirectional input and clipboard remain unverified.

## Original PR Status

All PRs below are closed without a direct merge. Closure alone does not mean
their functionality is upstream. The table distinguishes replacement work from
the residual implementation present in this stack.

| Original PR | Coverage at the pinned upstream commit |
| --- | --- |
| [#420: wall-press auto-release and Bounds](https://github.com/feschber/lan-mouse/pull/420) | Custom behavior retained. Integrated with upstream leave hooks. |
| [#429: CursorPos and cursor warps](https://github.com/feschber/lan-mouse/pull/429) | Stacked dependency; custom behavior retained. |
| [#430: suppress crossings while locked](https://github.com/feschber/lan-mouse/pull/430) | Custom behavior retained. |
| [#431: peer version exchange](https://github.com/feschber/lan-mouse/pull/431) | Already covered by merged [#458](https://github.com/feschber/lan-mouse/pull/458) before this refresh. |
| [#432: OS resolver and multi-homed listener](https://github.com/feschber/lan-mouse/pull/432) | OS resolver already upstream in [`a42592a`](https://github.com/feschber/lan-mouse/commit/a42592a); multi-homed listener remains custom. |
| [#433: mDNS primary-IP hints](https://github.com/feschber/lan-mouse/pull/433) | Custom behavior retained. |
| [#434: macOS quality-of-life bundle and UI polish](https://github.com/feschber/lan-mouse/pull/434) | Menu-bar behavior, TCC handling, bounded shutdown and UI changes remain custom. New upstream dylib packaging fixes complement, but do not replace, these features. |
| [#435: per-peer scroll and sensitivity](https://github.com/feschber/lan-mouse/pull/435) | Continuous-scroll tagging now covered by merged [#509](https://github.com/feschber/lan-mouse/pull/509). Per-peer controls remain custom. |
| [#436: dedicated GUI singleton socket](https://github.com/feschber/lan-mouse/pull/436) | Merged [#407](https://github.com/feschber/lan-mouse/pull/407) adds daemon reuse and GTK reactivation, a partial overlap. The previous stack did not contain the dedicated GUI socket; this refresh does not introduce it. |
| [#437: throttle Enter retries](https://github.com/feschber/lan-mouse/pull/437) | Custom behavior retained. |
| [#438: per-peer clipboard sync](https://github.com/feschber/lan-mouse/pull/438) | Custom behavior and application-source suppression retained. |

No equivalent merged replacement was found for the remaining custom features
in the inspected upstream history through the pinned commit.

## Newly Integrated Upstream Work

- [#407](https://github.com/feschber/lan-mouse/pull/407): reuse an existing daemon
  and present an existing GTK window.
- [#509](https://github.com/feschber/lan-mouse/pull/509): use one continuous-axis
  source tag for wlroots scrolling.
- [#448](https://github.com/feschber/lan-mouse/pull/448): leave hooks, including
  integration with the custom capture release paths.
- [#491](https://github.com/feschber/lan-mouse/pull/491): share the wlroots virtual
  keyboard.
- [#480](https://github.com/feschber/lan-mouse/pull/480) and
  [#485](https://github.com/feschber/lan-mouse/pull/485): libei session-change and
  layer-shell read-guard fixes.
- [#445](https://github.com/feschber/lan-mouse/pull/445): macOS PrintScreen,
  ScrollLock and Pause mappings to F13, F14 and F15.
- [#468](https://github.com/feschber/lan-mouse/pull/468) and
  [#505](https://github.com/feschber/lan-mouse/pull/505): macOS dylib resolution
  fixes and cargo-bundle metadata updates.

## Monitor Refresh PR

[#487: refresh macOS display bounds on hotplug](https://github.com/feschber/lan-mouse/pull/487)
is open, not a draft, and unmerged at this snapshot. GitHub reports it mergeable
with a clean merge state, but no reviews or status checks are reported. Its head
is `3d1549825e933caffd19e9d810c43d803e0fc928`; last update was 2026-08-28.
Mergeability is not CI verification or approval.

No upstream replacement was found. This stack retains the capture refresh and
its additional emulation union-origin fix. The PR itself is unchanged by this
refresh.
