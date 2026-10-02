// SPDX-License-Identifier: LGPL-3.0-or-later
// Copyright (C) 2026 s7commplus-rs contributors
// Ported from thomas-v2/S7CommPlusDriver Core/BlobDecompressor.cs, LGPL-3.0-or-later.

//! Optimized access: inflate of the zlib-compressed type-metadata blobs the PLC returns
//! for optimized (symbolic) blocks.
//!
//! These blobs are standard zlib streams that use **preset dictionaries**: the stream header
//! sets the `FDICT` bit and carries the dictionary's Adler-32 id, and inflate stops with
//! `Z_NEED_DICT` until that dictionary is supplied. The 19 dictionaries are embedded in
//! the `dict` module (extracted byte-exact from the reference `BlobDecompressor.cs`) and
//! selected by matching the reported Adler-32.
//!
//! This mirrors `BlobDecompressor.decompress(blob, startoffset)`. **Hardware-validated:** a real
//! compressed `IdentES` blob captured from a physical S7-1200 (DB1 attribute 2449, dictionary
//! `IdentES_98000001`) inflates to correct UTF-8 XML — see `real_hardware_identes_blob_golden`.
//! The blob carries a 4-byte version prefix, so callers pass `start_offset = 4`.

mod dict;

use flate2::{Decompress, FlushDecompress, Status};

use crate::error::{Error, Result};

/// Matches `BlobDecompressor.BLOB_DECOMPRESS_BUFSIZE` — the reference inflates into one 16 KiB
/// buffer. We stream in 16 KiB chunks instead, so larger blobs are handled too.
const CHUNK: usize = 16384;

/// Safety cap on the inflated output so a malformed/hostile blob cannot exhaust memory.
const MAX_OUTPUT: usize = 16 * 1024 * 1024;

/// Inflate a zlib-compressed S7CommPlus metadata blob, supplying the matching preset
/// dictionary if the stream requires one.
///
/// `start_offset` skips any leading prefix (some blobs carry a 4-byte dictionary-version
/// prefix before the zlib stream), mirroring the reference's `startoffset` argument.
///
/// Returns the raw inflated bytes (the reference decodes these as UTF-8 XML; callers can do
/// the same, but we return bytes so binary offset metadata is preserved losslessly).
pub fn decompress_blob(blob: &[u8], start_offset: usize) -> Result<Vec<u8>> {
    if start_offset > blob.len() {
        return Err(Error::protocol(format!(
            "blob start offset {start_offset} past end (len {})",
            blob.len()
        )));
    }
    let input = &blob[start_offset..];

    let mut dec = Decompress::new(true); // zlib-wrapped stream (has a header)
    let mut out = Vec::new();
    let mut buf = vec![0u8; CHUNK];
    let mut dict_tried = false;

    loop {
        let in_off = dec.total_in() as usize;
        let out_before = dec.total_out();
        let status = dec.decompress(&input[in_off..], &mut buf, FlushDecompress::Finish);
        let produced = (dec.total_out() - out_before) as usize;
        out.extend_from_slice(&buf[..produced]);
        if out.len() > MAX_OUTPUT {
            return Err(Error::protocol("decompressed blob exceeds the size cap"));
        }

        match status {
            Ok(Status::StreamEnd) => return Ok(out),
            Ok(Status::Ok) | Ok(Status::BufError) => {
                // Output buffer filled (or no forward progress possible). If nothing was
                // produced and all input is consumed, the stream is truncated/corrupt.
                if produced == 0 && dec.total_in() as usize >= input.len() {
                    return Err(Error::protocol("truncated or corrupt zlib blob"));
                }
                // Otherwise loop to drain more output.
            }
            Err(e) => {
                if let (false, Some(adler)) = (dict_tried, e.needs_dictionary()) {
                    let d = dict::PRESET_DICTIONARIES
                        .iter()
                        .find(|d| d.adler == adler)
                        .ok_or_else(|| {
                            Error::protocol(format!("no preset dictionary for id 0x{adler:08x}"))
                        })?;
                    log::debug!(
                        "blob inflate: applying preset dictionary {} (adler 0x{adler:08x})",
                        d.name
                    );
                    dec.set_dictionary(d.bytes).map_err(|e| {
                        Error::protocol(format!("inflateSetDictionary failed: {e}"))
                    })?;
                    dict_tried = true;
                    continue; // resume inflate now that the dictionary is set
                }
                return Err(Error::protocol(format!("zlib inflate failed: {e}")));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compress, Compression, FlushCompress};

    /// Round-trip through a real preset dictionary: compress a payload WITH the extracted
    /// dictionary (producing a zlib stream whose header sets FDICT + the dictionary's
    /// Adler-32), then confirm `decompress_blob` selects that dictionary and recovers the
    /// bytes exactly. This exercises the full `Z_NEED_DICT` -> set_dictionary -> inflate path
    /// against zlib using the genuine dictionary tables.
    fn roundtrip_with_dict(dict_bytes: &[u8], payload: &[u8]) {
        let mut comp = Compress::new(Compression::best(), true);
        comp.set_dictionary(dict_bytes).expect("set compress dict");
        let mut compressed = vec![0u8; payload.len() + dict_bytes.len() + 128];
        let status = comp
            .compress(payload, &mut compressed, FlushCompress::Finish)
            .expect("compress");
        assert!(
            matches!(status, Status::StreamEnd),
            "compress did not finish"
        );
        compressed.truncate(comp.total_out() as usize);

        let got = decompress_blob(&compressed, 0).expect("decompress");
        assert_eq!(got, payload, "round-trip mismatch");
    }

    #[test]
    fn dictionaries_are_loaded() {
        assert_eq!(dict::PRESET_DICTIONARIES.len(), 19);
        // The first dictionary's id must match its documented DICTID constant.
        let nwt = dict::PRESET_DICTIONARIES
            .iter()
            .find(|d| d.name == "NWT_98000001")
            .unwrap();
        assert_eq!(nwt.adler, 0x845f_c605);
    }

    #[test]
    fn every_dictionary_id_is_its_adler32() {
        // A stream names its dictionary by Adler-32, so a wrong id makes that dictionary
        // unreachable (upstream's NWT_90000001 constant has exactly that typo).
        fn adler32(data: &[u8]) -> u32 {
            let (mut a, mut b) = (1u32, 0u32);
            for &x in data {
                a = (a + u32::from(x)) % 65521;
                b = (b + a) % 65521;
            }
            (b << 16) | a
        }
        for d in dict::PRESET_DICTIONARIES {
            assert_eq!(d.adler, adler32(d.bytes), "dictionary {}", d.name);
        }
    }

    #[test]
    fn preset_dictionary_roundtrip() {
        let d = dict::PRESET_DICTIONARIES
            .iter()
            .find(|d| d.name == "DebugInfo_90000001")
            .unwrap();
        // Text that reuses fragments present in the dictionary compresses via the preset.
        roundtrip_with_dict(
            d.bytes,
            b"<DebugInfo><Network RefID=\"0\">Main Program Sweep (Cycle)</Network></DebugInfo>",
        );
    }

    #[test]
    fn start_offset_past_end_errors() {
        assert!(decompress_blob(&[0x01, 0x02], 5).is_err());
    }

    #[test]
    fn garbage_is_rejected_not_panicked() {
        assert!(decompress_blob(&[0x00, 0x11, 0x22, 0x33, 0x44], 0).is_err());
    }

    #[test]
    fn real_hardware_identes_blob_golden() {
        // Captured live from a physical S7-1200: DB1 attribute 2449 (a compressed
        // InterfaceDescription / IdentES blob). It has a 4-byte version prefix (0x98000002)
        // then a zlib stream with FDICT set whose dictionary id (Adler-32 0x5814b03b) selects
        // the `IdentES_98000001` preset dictionary. This closes the L6 blob-inflate gate with
        // real optimized-block data.
        let blob = include_bytes!("../../tests/vectors/optimized/identes_db1.bin");
        let out = decompress_blob(blob, 4).expect("inflate real IdentES blob");
        let xml = String::from_utf8(out).expect("IdentES blob is UTF-8 XML");
        assert!(
            xml.starts_with("<IdentES version=\"2.0\">"),
            "unexpected start: {xml:.40}"
        );
        assert!(xml.contains("<TargetFamily>S71200</TargetFamily>"));
        // The block name is Cyrillic — verifies non-ASCII survives inflate + UTF-8 decode.
        assert!(xml.contains("ofname=\"Датчики\""));
        assert!(xml.ends_with("</IdentES>"));
    }
}
