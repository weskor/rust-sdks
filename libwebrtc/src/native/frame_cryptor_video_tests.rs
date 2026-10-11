// Copyright 2026 Den contributors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Real VP8 -> SRTP -> AES-GCM -> native decoder loopback, without services or devices.
// The stream is installed before negotiation, not from on_track, so startup media
// is observable even before the application can attach a receiver cryptor.

use std::{
    future::poll_fn,
    pin::Pin,
    sync::{
        atomic::{AtomicU8, Ordering},
        Arc,
    },
    time::Duration,
};

use livekit_runtime::Stream;
use tokio::{sync::mpsc, task::JoinHandle, time};

use super::{
    EncryptionAlgorithm, FrameCryptor, KeyDerivationAlgorithm, KeyProvider, KeyProviderOptions,
};
use crate::{
    media_stream_track::MediaStreamTrack,
    peer_connection::{AnswerOptions, OfferOptions, PeerConnection},
    peer_connection_factory::{
        native::PeerConnectionFactoryExt, PeerConnectionFactory, RtcConfiguration,
    },
    rtp_receiver::RtpReceiver,
    rtp_sender::RtpSender,
    rtp_transceiver::{RtpTransceiverDirection, RtpTransceiverInit},
    stats::RtcStats,
    video_frame::{BoxVideoFrame, I420Buffer, VideoBuffer, VideoFrame, VideoRotation},
    video_source::{native::NativeVideoSource, VideoResolution},
    video_stream::native::NativeVideoStream,
    MediaType,
};

const PARTICIPANT: &str = "authenticated-video-sender";
const KEY: [u8; 32] = [7; 32];
const WIDTH: u32 = 64;
const HEIGHT: u32 = 48;
const QUIET_INTERVAL: Duration = Duration::from_millis(750);
const FRAME_TIMEOUT: Duration = Duration::from_secs(10);

fn key_provider() -> KeyProvider {
    KeyProvider::new(KeyProviderOptions {
        shared_key: false,
        ratchet_window_size: 0,
        ratchet_salt: b"native-vp8-regression".to_vec(),
        failure_tolerance: -1,
        key_ring_size: 16,
        key_derivation_algorithm: KeyDerivationAlgorithm::PBKDF2,
    })
}

fn pattern(luma: u8) -> VideoFrame<I420Buffer> {
    let mut buffer = I420Buffer::new(WIDTH, HEIGHT);
    let (y, u, v) = buffer.data_mut();
    for row in 0..HEIGHT as usize {
        for col in 0..WIDTH as usize {
            y[row * WIDTH as usize + col] = luma
                + if (row >= HEIGHT as usize / 2) ^ (col >= WIDTH as usize / 2) { 32 } else { 0 };
        }
    }
    u.fill(90);
    v.fill(170);
    VideoFrame::new(VideoRotation::VideoRotation0, buffer)
}

struct Loopback {
    sender: PeerConnection,
    receiver: PeerConnection,
    rtp_sender: RtpSender,
    rtp_receiver: RtpReceiver,
    stream: NativeVideoStream,
    luma: Arc<AtomicU8>,
    tasks: Vec<JoinHandle<()>>,
}

impl Loopback {
    fn new(factory: &PeerConnectionFactory, require_sender_encryption: bool) -> Self {
        let sender_config = RtcConfiguration {
            require_frame_encryption: require_sender_encryption,
            ..RtcConfiguration::default()
        };
        let receiver_config =
            RtcConfiguration { require_frame_encryption: true, ..RtcConfiguration::default() };
        let sender = factory.create_peer_connection(sender_config).unwrap();
        let receiver = factory.create_peer_connection(receiver_config).unwrap();
        // Own the peers immediately: every later assertion/panic must close them.
        let mut peers =
            PeerCleanup { sender: sender.clone(), receiver: receiver.clone(), armed: true };
        let source =
            NativeVideoSource::new(VideoResolution { width: WIDTH, height: HEIGHT }, false);
        // Stop the source's initial black keepalive before publishing a track.
        source.capture_frame(&pattern(48));
        let track = factory.create_video_track("encrypted-vp8-regression", source.clone());
        let sending = sender
            .add_transceiver(
                track.into(),
                RtpTransceiverInit {
                    direction: RtpTransceiverDirection::SendOnly,
                    stream_ids: vec!["native-loopback".into()],
                    send_encodings: Vec::new(),
                },
            )
            .unwrap();
        let receiving = receiver
            .add_transceiver_for_media(
                MediaType::Video,
                RtpTransceiverInit {
                    direction: RtpTransceiverDirection::RecvOnly,
                    stream_ids: Vec::new(),
                    send_encodings: Vec::new(),
                },
            )
            .unwrap();
        let vp8: Vec<_> = factory
            .get_rtp_sender_capabilities(MediaType::Video)
            .codecs
            .into_iter()
            .filter(|codec| codec.mime_type.eq_ignore_ascii_case("video/VP8"))
            .collect();
        assert!(!vp8.is_empty(), "native regression requires the software VP8 codec");
        sending.set_codec_preferences(vp8.clone()).unwrap();
        receiving.set_codec_preferences(vp8).unwrap();
        let rtp_receiver = receiving.receiver();
        let Some(MediaStreamTrack::Video(track)) = rtp_receiver.track() else {
            panic!("pre-negotiation video transceiver must expose its receiver track");
        };
        let stream = NativeVideoStream::new(track);
        let luma = Arc::new(AtomicU8::new(48));
        let capture_luma = luma.clone();
        let capture = tokio::spawn(async move {
            let mut current = 48;
            let mut frame = pattern(current);
            let mut interval = time::interval(Duration::from_millis(33));
            interval.set_missed_tick_behavior(time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let next = capture_luma.load(Ordering::Relaxed);
                if next != current {
                    // Never mutate a buffer still retained by the native encoder.
                    frame = pattern(next);
                    current = next;
                }
                source.capture_frame(&frame);
            }
        });
        let loopback = Self {
            sender,
            receiver,
            rtp_sender: sending.sender(),
            rtp_receiver,
            stream,
            luma,
            tasks: vec![capture],
        };
        peers.armed = false;
        loopback
    }

    async fn negotiate(&mut self) {
        let (sender_ice, mut sender_candidates) = mpsc::unbounded_channel();
        let (receiver_ice, mut receiver_candidates) = mpsc::unbounded_channel();
        self.sender.on_ice_candidate(Some(Box::new(move |candidate| {
            let _ = sender_ice.send(candidate);
        })));
        self.receiver.on_ice_candidate(Some(Box::new(move |candidate| {
            let _ = receiver_ice.send(candidate);
        })));
        let offer = self.sender.create_offer(OfferOptions::default()).await.unwrap();
        self.sender.set_local_description(offer.clone()).await.unwrap();
        self.receiver.set_remote_description(offer).await.unwrap();
        let answer = self.receiver.create_answer(AnswerOptions::default()).await.unwrap();
        self.receiver.set_local_description(answer.clone()).await.unwrap();
        self.sender.set_remote_description(answer).await.unwrap();
        // Forward every local ICE candidate, but only once remote SDP exists.
        let receiver = self.receiver.clone();
        self.tasks.push(tokio::spawn(async move {
            while let Some(candidate) = sender_candidates.recv().await {
                if receiver.add_ice_candidate(candidate).await.is_err() {
                    break;
                }
            }
        }));
        let sender = self.sender.clone();
        self.tasks.push(tokio::spawn(async move {
            while let Some(candidate) = receiver_candidates.recv().await {
                if sender.add_ice_candidate(candidate).await.is_err() {
                    break;
                }
            }
        }));
        time::timeout(FRAME_TIMEOUT, async {
            while self.received_packets().await == 0 {
                time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("local VP8 RTP must flow before testing receiver gates");
    }

    async fn received_packets(&self) -> u64 {
        self.receiver
            .get_stats()
            .await
            .unwrap()
            .into_iter()
            .filter_map(|stat| match stat {
                RtcStats::InboundRtp(stat) if stat.stream.kind == "video" => {
                    Some(stat.received.packets_received)
                }
                _ => None,
            })
            .sum()
    }

    async fn expect_no_frames(&mut self, phase: &str) {
        let before = self.received_packets().await;
        let result =
            time::timeout(QUIET_INTERVAL, poll_fn(|cx| Pin::new(&mut self.stream).poll_next(cx)))
                .await;
        assert!(result.is_err(), "decoded video escaped the receive gate: {phase}");
        assert!(
            self.received_packets().await > before,
            "silence must be observed while real VP8 RTP arrives: {phase}"
        );
    }

    async fn expect_pattern(&mut self, luma: u8) {
        self.luma.store(luma, Ordering::Relaxed);
        time::timeout(FRAME_TIMEOUT, async {
            loop {
                let frame = poll_fn(|cx| Pin::new(&mut self.stream).poll_next(cx))
                    .await
                    .expect("native video sink closed before authenticated video decoded");
                if matches_pattern(&frame, luma) {
                    break;
                }
            }
        })
        .await
        .expect("matching AES-GCM key must deliver the expected VP8 pixels");
    }
}

impl Drop for Loopback {
    fn drop(&mut self) {
        self.sender.close();
        self.receiver.close();
        for task in &self.tasks {
            task.abort();
        }
        self.stream.close();
    }
}

struct PeerCleanup {
    sender: PeerConnection,
    receiver: PeerConnection,
    armed: bool,
}

impl Drop for PeerCleanup {
    fn drop(&mut self) {
        if self.armed {
            self.sender.close();
            self.receiver.close();
        }
    }
}

fn matches_pattern(frame: &BoxVideoFrame, luma: u8) -> bool {
    let Some(buffer) = frame.buffer.as_i420() else { return false };
    if buffer.width() != WIDTH || buffer.height() != HEIGHT {
        return false;
    }
    let (y, u, v) = buffer.data();
    let (stride_y, stride_u, stride_v) = buffer.strides();
    // Sample well inside all four quadrants; VP8 is lossy, so permit a small
    // quantization error, not arbitrary decoded output or a black keepalive.
    for (col, row, expected) in
        [(16, 12, luma), (48, 12, luma + 32), (16, 36, luma + 32), (48, 36, luma)]
    {
        if y[row * stride_y as usize + col].abs_diff(expected) > 8 {
            return false;
        }
        if u[(row / 2) * stride_u as usize + col / 2].abs_diff(90) > 8
            || v[(row / 2) * stride_v as usize + col / 2].abs_diff(170) > 8
        {
            return false;
        }
    }
    true
}

fn sender_cryptor(factory: &PeerConnectionFactory, loopback: &Loopback) -> FrameCryptor {
    let provider = key_provider();
    assert!(provider.set_key(PARTICIPANT.into(), 0, KEY.to_vec()));
    let cryptor = FrameCryptor::new_for_rtp_sender(
        factory,
        PARTICIPANT.into(),
        EncryptionAlgorithm::AesGcm,
        provider,
        loopback.rtp_sender.clone(),
    );
    cryptor.set_key_index(0);
    cryptor.set_enabled(true);
    cryptor
}

fn receiver_cryptor(
    factory: &PeerConnectionFactory,
    loopback: &Loopback,
    participant: &str,
    provider: KeyProvider,
) -> FrameCryptor {
    let cryptor = FrameCryptor::new_for_rtp_receiver(
        factory,
        participant.into(),
        EncryptionAlgorithm::AesGcm,
        provider,
        loopback.rtp_receiver.clone(),
    );
    assert!(cryptor.enabled(), "receiver must be enabled at attachment without a key");
    cryptor
}

#[tokio::test]
async fn required_vp8_receiver_decrypts_only_with_matching_key() {
    time::timeout(Duration::from_secs(45), async {
        let factory = PeerConnectionFactory::default();
        // Only this sender opts out, deliberately: plaintext VP8 must be sent to
        // prove the required receiver's pre-cryptor gate, not just decoder rejection
        // of ciphertext. The receiver requires encryption throughout the test.
        let mut loopback = Loopback::new(&factory, false);
        loopback.negotiate().await;
        loopback.expect_no_frames("plaintext before receiver cryptor attachment").await;
        let sender = sender_cryptor(&factory, &loopback);
        loopback.expect_no_frames("ciphertext before receiver cryptor attachment").await;
        let provider = key_provider();
        let receiver = receiver_cryptor(&factory, &loopback, PARTICIPANT, provider.clone());
        loopback.expect_no_frames("receiver key absent").await;
        assert!(provider.set_key(PARTICIPANT.into(), 0, vec![8; 32]));
        loopback.expect_no_frames("receiver key wrong").await;
        assert!(provider.set_key(PARTICIPANT.into(), 0, KEY.to_vec()));
        loopback.expect_pattern(48).await;
        loopback.expect_pattern(128).await;
        loopback.expect_pattern(80).await;
        // Keep both transformers attached until all decoded-frame assertions finish.
        drop((receiver, sender));
    })
    .await
    .expect("required native VP8 key lifecycle loopback must finish");
}

#[tokio::test]
async fn required_vp8_pending_cryptor_can_be_replaced() {
    time::timeout(Duration::from_secs(45), async {
        let factory = PeerConnectionFactory::default();
        let mut loopback = Loopback::new(&factory, true);
        let sender = sender_cryptor(&factory, &loopback);
        loopback.negotiate().await;
        loopback.expect_no_frames("ciphertext before receiver cryptor attachment").await;
        let pending = receiver_cryptor(&factory, &loopback, "pending-video", key_provider());
        loopback.expect_no_frames("keyless pending receiver cryptor").await;
        let authenticated_provider = key_provider();
        assert!(authenticated_provider.set_key(PARTICIPANT.into(), 0, KEY.to_vec()));
        let authenticated =
            receiver_cryptor(&factory, &loopback, PARTICIPANT, authenticated_provider);
        // The old cryptor is still alive when the new transformer is installed,
        // as during an authenticated track-mapping cutover. Its eventual drop
        // must not detach the replacement or enable plaintext bypass.
        drop(pending);
        loopback.expect_pattern(48).await;
        loopback.expect_pattern(128).await;
        loopback.expect_pattern(80).await;
        drop((authenticated, sender));
    })
    .await
    .expect("required native VP8 pending-cryptor replacement loopback must finish");
}
