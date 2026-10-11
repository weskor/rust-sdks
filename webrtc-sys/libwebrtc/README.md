This directory can contain a checkout of WebRTC. The build scripts
install dependencies, check out the immutable revision pinned in `.gclient`,
apply the fork's patches, and build it. For a Linux release build on x64:

```sh
$ ./build_linux.sh --arch x64 --profile release
```

After running this, `linux-x64-release/lib/libwebrtc.a` should
exist. This can be rerun to rebuild it, but will complain about
patches not applying as they have already been applied.

If something goes wrong it may be helpful to consult the [WebRTC native
development documentation](https://webrtc.googlesource.com/src/+/main/docs/native-code/development/).

## Den encrypted-video artifacts

Linux and Windows use the `webrtc-den-gated-video-89d790b` release in
`weskor/rust-sdks`, built from WebRTC
`89d790b40447c3c5c54c3edd58aa53d285e35fa7`. Other platforms retain the
upstream `livekit/rust-sdks` artifacts.

`patches/gated_video_frame_transformer.patch` preserves the required-encryption
startup gate while routing video through the encoded-frame transformer after
the synchronous decryptor. The binding's synchronous decryptor is a copy-only
gate; AES-GCM authentication/decryption happens in the always-enabled
`FrameCryptorTransformer`. Without this patch, video bypasses that transformer
and ciphertext reaches the decoder.

`cargo test -p libwebrtc required_vp8` exercises real VP8/SRTP media: no decoded
video before cryptor attachment, with an absent or wrong key, or while a
keyless cryptor is pending; changing pixels decode after the matching key or
authenticated replacement is installed. The fixture observes the negotiated
`on_track` receiver, since remote SDP can replace provisional receiver handles.


# Building the Rust bindings with a custom WebRTC artifact

Add the following environment variable to `.cargo/config.toml` to
use a custom WebRTC build:

```toml
[env]
LK_CUSTOM_WEBRTC = { value = "webrtc-sys/libwebrtc/linux-x64-release", relative = true }
```

Replace `linux-x64-release` with the artifact
directory appropriate for your configuration.
