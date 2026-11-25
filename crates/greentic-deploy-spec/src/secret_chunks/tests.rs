use super::*;

fn data(length: usize) -> Vec<u8> {
    let mut state = 0x491ad35bu32;
    (0..length)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state as u8
        })
        .collect()
}
fn manifest(bytes: &[u8]) -> ChunkManifest {
    let versions = (1..=bytes.len().div_ceil(CHUNK_BYTES))
        .map(|i| i.to_string())
        .collect::<Vec<_>>();
    ChunkManifest::new(bytes, &versions).unwrap()
}
#[test]
fn exact_boundary_and_reported_and_multi_megabyte_sizes() {
    assert!(check_store_length(65_536).is_err()); // legacy transport
    for len in [65_537, 70_737, 2 * 1024 * 1024 + 17, MAX_STORE_BYTES] {
        let bytes = data(len);
        let m = manifest(&bytes);
        assert!(m.encode().unwrap().len() < SECRET_VERSION_CAP);
        assert!(m.chunks.iter().all(|c| c.length < SECRET_VERSION_CAP));
        let m = ChunkManifest::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(
            m.reconstruct(|c| Ok(
                bytes[c.index * CHUNK_BYTES..c.index * CHUNK_BYTES + c.length].to_vec()
            ))
            .unwrap(),
            bytes
        );
    }
    assert!(check_store_length(MAX_STORE_BYTES + 1).is_err());
}
#[test]
fn corrupt_missing_reordered_duplicate_and_unpinned_chunks_fail_closed() {
    let bytes = data(70_737);
    let good = manifest(&bytes);
    assert!(
        good.reconstruct(|_| Err(ChunkError("missing chunk")))
            .is_err()
    );
    assert!(good.reconstruct(|c| Ok(vec![0; c.length])).is_err());
    for case in 0..7 {
        let mut m = good.clone();
        match case {
            0 => m.chunks.swap(0, 1),
            1 => m.chunks[1] = m.chunks[0].clone(),
            2 => m.chunks[1].version = m.chunks[0].version.clone(),
            3 => m.chunks[0].path = "../../credential".into(),
            4 => m.chunks[0].version = "latest".into(),
            5 => m.chunks.pop().map(|_| ()).unwrap(),
            _ => m.schema = "unknown".into(),
        }
        assert!(m.validate().is_err());
    }
    let mut m = good;
    m.sha256 = "0".repeat(64);
    assert!(
        m.reconstruct(|c| Ok(
            bytes[c.index * CHUNK_BYTES..c.index * CHUNK_BYTES + c.length].to_vec()
        ))
        .is_err()
    );
}
#[test]
fn malformed_json_never_echoes_credential_values() {
    let secret = b"{\"schema\":\"sensitive-credential-content\",\"length\":\"private-value\"}";
    let error = ChunkManifest::decode(secret).unwrap_err().to_string();
    assert!(!error.contains("sensitive-credential-content"));
    assert!(!error.contains("private-value"));
}
