---
libwebrtc: patch
webrtc-sys: patch
webrtc-sys-build: patch
---

Preserve fail-closed receive startup while routing gated video through the encoded-frame transformer before decoding. Use the narrowly patched Linux and Windows WebRTC artifacts from the Den fork, pinned to the original native source revision. Add real VP8/SRTP/AES-GCM regressions for startup gating, absent and wrong keys, matching-key recovery, and replacing a pending keyless receiver cryptor.
