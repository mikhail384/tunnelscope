//! Wire compatibility with CSQTT 2.1.9, focsq and vk-turn-proxy-ios.
use anyhow::{Result, anyhow, bail};
use ctr::cipher::{InnerIvInit, KeyInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::ops::Range;

pub const WIRE_V2: &str = "CSQTT-WIRE-2";
pub const WIRE_V3: &str = "CSQTT-WIRE-3";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(u8)]
pub enum DataMode {
    #[default]
    Native = 0,
    Legacy = 1,
    Framed = 2,
}

impl DataMode {
    pub fn stream_revision(self) -> &'static str {
        if self == Self::Framed {
            "stream-v2"
        } else {
            "stream-v1"
        }
    }
    pub fn from_u8(value: u8) -> Self {
        match value {
            1 => Self::Legacy,
            2 => Self::Framed,
            _ => Self::Native,
        }
    }
}

pub struct ConfigRequest<'a> {
    pub port: &'a str,
    pub device: &'a str,
    pub password: &'a str,
    pub generation: &'a str,
    pub salt: &'a str,
    pub worker: &'a str,
    pub desired: &'a str,
    pub mode: DataMode,
}

pub fn parse_config_request(text: &str) -> Option<ConfigRequest<'_>> {
    let parts: Vec<_> = text
        .strip_prefix("GETCONF:")?
        .trim()
        .split('|')
        .map(str::trim)
        .collect();
    // The revision field determines the layout, even for an all-digit password.
    let legacy = parts.len() >= 8;
    let at = |i| parts.get(i).copied().unwrap_or("");
    let (device, offset, mode) = if legacy {
        let mode = match at(7) {
            WIRE_V2 => DataMode::Legacy,
            WIRE_V3 => DataMode::Framed,
            _ => return None,
        };
        if at(1).is_empty() || at(1).len() > 128 {
            return None;
        }
        (at(1), 1, mode)
    } else {
        ("", 0, DataMode::Native)
    };
    if parts.len() < 3 + offset {
        return None;
    }
    Some(ConfigRequest {
        port: at(0),
        device,
        password: at(1 + offset),
        generation: at(2 + offset),
        salt: at(3 + offset),
        worker: at(4 + offset),
        desired: at(5 + offset),
        mode,
    })
}

pub fn legacy_request(
    port: &str,
    device: &str,
    password: &str,
    generation: u64,
    salt: &str,
    worker: usize,
    desired: usize,
) -> String {
    format!("GETCONF:{port}|{device}|{password}|{generation}|{salt}|{worker}|{desired}|{WIRE_V2}")
}

/// Legacy SRTP leaves RTP padding outside AES; PT 111 uses ChaCha20-Poly1305.
/// Both formats authenticate the RTP header before accepting any plaintext.
pub struct LegacyCipher {
    aes: aes::Aes128,
    hmac: Hmac<Sha1>,
    chacha: aws_lc_rs::aead::LessSafeKey,
}

impl LegacyCipher {
    pub fn new(key: &[u8; 32]) -> Result<Self> {
        Ok(Self {
            aes: aes::Aes128::new_from_slice(&key[..16]).map_err(|_| anyhow!("AES key"))?,
            hmac: <Hmac<Sha1> as hmac::digest::KeyInit>::new_from_slice(&key[16..])
                .map_err(|_| anyhow!("HMAC key"))?,
            chacha: aws_lc_rs::aead::LessSafeKey::new(
                aws_lc_rs::aead::UnboundKey::new(&aws_lc_rs::aead::CHACHA20_POLY1305, key)
                    .map_err(|_| anyhow!("ChaCha key"))?,
            ),
        })
    }

    pub fn open(&self, wire: &mut [u8]) -> Result<Range<usize>> {
        let header_len = header_len(wire)?;
        let audio = wire[1] & 0x7f == 111;
        let tag_len = if audio { 16 } else { 10 };
        let mut end = wire.len();
        if !audio {
            if end < header_len + tag_len {
                bail!("missing SRTP tag");
            }
            end -= tag_len;
            let mut mac = self.hmac.clone();
            mac.update(&wire[..end]);
            mac.verify_truncated_left(&wire[end..])
                .map_err(|_| anyhow!("SRTP authentication failed"))?;
        }
        if wire[0] & 0x20 != 0 {
            let padding = wire[end - 1] as usize;
            if padding == 0
                || padding > end.saturating_sub(header_len + if audio { tag_len } else { 0 })
            {
                bail!("invalid legacy RTP padding");
            }
            end -= padding;
        }
        if audio {
            if end < header_len + tag_len {
                bail!("missing audio tag");
            }
            let tag_start = end - tag_len;
            let tag: [u8; 16] = wire[tag_start..end].try_into()?;
            let nonce = nonce(wire);
            let (aad, encrypted) = wire.split_at_mut(header_len);
            self.chacha
                .open_in_place_separate_tag(
                    aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce),
                    aws_lc_rs::aead::Aad::from(aad),
                    &tag,
                    &mut encrypted[..tag_start - header_len],
                )
                .map_err(|_| anyhow!("audio authentication failed"))?;
            end = tag_start;
        } else {
            let mut iv = [0; 16];
            iv[..12].copy_from_slice(&nonce(wire));
            type Core = ctr::CtrCore<aes::Aes128, ctr::flavors::Ctr128BE>;
            let mut cipher = ctr::Ctr128BE::<aes::Aes128>::from_core(Core::inner_iv_init(
                self.aes.clone(),
                (&iv).into(),
            ));
            cipher.apply_keystream(&mut wire[header_len..end]);
        }
        Ok(header_len..end)
    }

    pub fn seal(
        &self,
        header: &[u8; 24],
        plain: &[u8],
        padding: &[u8],
        out: &mut [u8],
    ) -> Result<usize> {
        let audio = header[1] & 0x7f == 111;
        let tag_len = if audio { 16 } else { 10 };
        let total = 24 + plain.len() + tag_len + padding.len();
        if out.len() < total || padding.is_empty() || padding.len() > 255 {
            bail!("legacy packet capacity");
        }
        out[..24].copy_from_slice(header);
        out[24..24 + plain.len()].copy_from_slice(plain);
        let payload_end = 24 + plain.len();
        let pad_start = payload_end + if audio { tag_len } else { 0 };
        out[pad_start..pad_start + padding.len()].copy_from_slice(padding);
        out[pad_start + padding.len() - 1] = padding.len() as u8;
        if audio {
            let tag = self
                .chacha
                .seal_in_place_separate_tag(
                    aws_lc_rs::aead::Nonce::assume_unique_for_key(nonce(header)),
                    aws_lc_rs::aead::Aad::from(header.as_slice()),
                    &mut out[24..payload_end],
                )
                .map_err(|_| anyhow!("audio encryption failed"))?;
            out[payload_end..payload_end + 16].copy_from_slice(tag.as_ref());
        } else {
            let mut iv = [0; 16];
            iv[..12].copy_from_slice(&nonce(header));
            type Core = ctr::CtrCore<aes::Aes128, ctr::flavors::Ctr128BE>;
            let mut cipher = ctr::Ctr128BE::<aes::Aes128>::from_core(Core::inner_iv_init(
                self.aes.clone(),
                (&iv).into(),
            ));
            cipher.apply_keystream(&mut out[24..payload_end]);
            let tag_start = total - 10;
            let mut mac = self.hmac.clone();
            mac.update(&out[..tag_start]);
            out[tag_start..total].copy_from_slice(&mac.finalize().into_bytes()[..10]);
        }
        Ok(total)
    }
}

fn nonce(header: &[u8]) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&header[8..12]);
    nonce[4..6].copy_from_slice(&header[2..4]);
    nonce[8..12].copy_from_slice(&header[4..8]);
    nonce
}

fn header_len(wire: &[u8]) -> Result<usize> {
    if wire.len() < 12 || wire[0] >> 6 != 2 || !matches!(wire[1] & 0x7f, 111 | 96 | 6) {
        bail!("invalid legacy RTP header");
    }
    let mut len = 12 + usize::from(wire[0] & 0x0f) * 4;
    if wire[0] & 0x10 != 0 {
        if wire.len() < len + 4 {
            bail!("missing RTP extension");
        }
        len += 4 + usize::from(u16::from_be_bytes([wire[len + 2], wire[len + 3]])) * 4;
    }
    if wire.len() <= len {
        bail!("empty RTP payload");
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_password_uses_versioned_layout() {
        let c =
            parse_config_request("GETCONF:9000|device|12345678|7|salt|1|126|CSQTT-WIRE-3").unwrap();
        assert_eq!(c.password, "12345678");
        assert_eq!(c.generation, "7");
        assert_eq!(c.mode, DataMode::Framed);
        assert!(
            parse_config_request("GETCONF:9000|device|password|7|salt|1|3|CSQTT-WIRE-99").is_none()
        );
    }

    #[test]
    fn opens_published_219_audio_datagram() {
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(Some(b"CSQTT-WRAP-v1"), b"wire-password");
        let mut key = [0; 32];
        hk.expand(b"rtp-obfs/chacha20poly1305", &mut key).unwrap();
        let mut wire = hex::decode("b06f77881122334410203040bede0002325566775199aa009e2a813c2df794354293ade7b0b8ef4aa6297cf3cc8b0a372342fbd678c10260dc543f8338262292992b12600eaa12d0d3155fa7179b62cd34ac41afb32db0ab7f6dced9e1bb0620daa26d1743f2c25af6bd9ade9901").unwrap();
        let range = LegacyCipher::new(&key).unwrap().open(&mut wire).unwrap();
        assert_eq!(
            &wire[range],
            b"GETCONF:46000|wire-device|wire-password|7|wire-salt|1|27|CSQTT-WIRE-2"
        );
    }

    #[test]
    fn published_go_audio_and_video_vectors_match_in_both_directions() {
        let hk =
            hkdf::Hkdf::<sha2::Sha256>::new(Some(b"CSQTT-WRAP-v1"), b"cross-language-password");
        let mut key = [0; 32];
        hk.expand(b"rtp-obfs/chacha20poly1305", &mut key).unwrap();
        let cipher = LegacyCipher::new(&key).unwrap();
        for encoded in [
            "b06f9e5243e8f72f8b6fe47dbede00023211eb8551beef00ef3c0513fb6f0307716f44a2af1324af6b39f3b165e81c752be49913911ad0fd782649a54cc4f984cef050cce1b4d509cbae4d6e9359b57e0b9615",
            "b060cb1b7b25bb36709a0949bede00023211eb85512bb6004aac7f46ac97f3ef8522a3af2b8b4b536bc0b342d567aa5faa2ea4ecb07d22daf20c38ca989cda177175ab00",
        ] {
            let golden = hex::decode(encoded).unwrap();
            let mut wire = golden.clone();
            let range = cipher.open(&mut wire).unwrap();
            assert_eq!(&wire[range.clone()], b"cross-language-payload");
            let audio = wire[1] & 0x7f == 111;
            let padding = if audio {
                &golden[range.end + 16..]
            } else {
                &golden[range.end..golden.len() - 10]
            };
            let mut output = [0; 2048];
            let len = cipher
                .seal(
                    golden[..24].try_into().unwrap(),
                    &wire[range],
                    padding,
                    &mut output,
                )
                .unwrap();
            assert_eq!(&output[..len], golden);
        }
    }

    #[test]
    fn audio_and_video_authenticate_header_payload_and_tag() {
        let cipher = LegacyCipher::new(&[7; 32]).unwrap();
        for pt in [111, 96] {
            let mut header = [0; 24];
            header[0] = 0xb0;
            header[1] = pt;
            header[12..16].copy_from_slice(&[0xbe, 0xde, 0, 2]);
            let mut wire = [0; 2048];
            let len = cipher
                .seal(&header, b"READY", &[0, 0, 3], &mut wire)
                .unwrap();
            for i in [2, 24, 30] {
                let mut corrupt = wire[..len].to_vec();
                corrupt[i] ^= 1;
                assert!(cipher.open(&mut corrupt).is_err());
            }
            let range = cipher.open(&mut wire[..len]).unwrap();
            assert_eq!(&wire[range], b"READY");
        }
    }
}
