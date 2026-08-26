/// Compute 64-bit FNV-1a hash of a byte slice.
#[inline]
pub fn fnv64a(bytes: &[u8]) -> u64 {
    const FNV_PRIME: u64 = 1099511628211;
    const FNV_OFFSET_BASIS: u64 = 14695981039346656037;

    let mut hash = FNV_OFFSET_BASIS;
    for &byte in bytes {
        hash ^= byte as u64;
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

/// Compute 64-bit Charikar SimHash over tokenized string/shingles.
pub fn simhash64<I, S>(tokens: I) -> u64
where
    I: IntoIterator<Item = S>,
    S: AsRef<[u8]>,
{
    let mut v = [0i32; 64];

    for token in tokens {
        let hash = fnv64a(token.as_ref());
        for i in 0..64 {
            if (hash & (1 << i)) != 0 {
                v[i] += 1;
            } else {
                v[i] -= 1;
            }
        }
    }

    let mut fingerprint = 0u64;
    for i in 0..64 {
        if v[i] > 0 {
            fingerprint |= 1 << i;
        }
    }

    fingerprint
}

/// Compute Hamming distance between two 64-bit integers.
#[inline]
pub fn hamming_distance(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// In-memory SimHash cluster index with budget tracking.
#[derive(Debug, Clone, Default)]
pub struct SimHashIndex {
    signatures: Vec<u64>,
    max_hamming_distance: u32,
}

impl SimHashIndex {
    pub fn new(max_hamming_distance: u32) -> Self {
        Self {
            signatures: Vec::new(),
            max_hamming_distance,
        }
    }

    /// Check if fingerprint is unique (or within distance budget).
    /// Returns true if accepted (unique), false if filtered as similar.
    pub fn accept(&mut self, fp: u64) -> bool {
        for &existing in &self.signatures {
            if hamming_distance(existing, fp) <= self.max_hamming_distance {
                return false;
            }
        }
        self.signatures.push(fp);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hamming_distance() {
        assert_eq!(hamming_distance(0, 0), 0);
        assert_eq!(hamming_distance(0b0101, 0b0111), 1);
        assert_eq!(hamming_distance(0xFFFFFFFFFFFFFFFF, 0), 64);
    }

    #[test]
    fn test_simhash_similarity() {
        let doc1 = ["katana", "crawler", "recon", "security", "endpoint"];
        let doc2 = ["katana", "crawler", "recon", "security", "parameter"];
        let doc3 = ["completely", "unrelated", "random", "recipe", "cooking"];

        let fp1 = simhash64(doc1);
        let fp2 = simhash64(doc2);
        let fp3 = simhash64(doc3);

        let dist_1_2 = hamming_distance(fp1, fp2);
        let dist_1_3 = hamming_distance(fp1, fp3);

        assert!(dist_1_2 < dist_1_3, "Similar documents must have lower Hamming distance");
    }
}
