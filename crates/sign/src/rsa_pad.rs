//! RSA signature checks with the padding done here: the raw public-key operation comes from the
//! `rsa` crate, and the EMSA-PKCS1-v1_5 / EMSA-PSS encodings (RFC 8017 §9) are checked against
//! any digest, any MGF1 hash and any salt length, which the `rsa` crate's typed API can't do.
//! Verification only; public data, so nothing here needs to be constant-time.

use rsa::{BoxedUint, RsaPublicKey};

use crate::SignError;
use crate::der;
use crate::keys::{DigestAlg, PssParams};

/// The encoded message `sig^e mod n` as exactly `n.len()` bytes, or `None` if the signature is
/// out of range. `n` is the modulus without leading zeros.
fn encoded_message(n: &[u8], e: &[u8], sig: &[u8]) -> Result<Option<Vec<u8>>, SignError> {
    let k = n.len();
    let key = RsaPublicKey::new(BoxedUint::from_be_slice_vartime(n), BoxedUint::from_be_slice_vartime(e))
        .map_err(|e| SignError::Malformed(format!("RSA key: {e}")))?;
    // Some signers drop leading zero bytes of the signature.
    let sig = match sig.iter().position(|b| *b != 0) {
        Some(i) => sig.get(i..).unwrap_or_default(),
        None => return Ok(None),
    };
    if sig.len() > k {
        return Ok(None);
    }
    let Ok(em) = rsa::hazmat::rsa_encrypt(&key, &BoxedUint::from_be_slice_vartime(sig)) else { return Ok(None) };
    let bytes = em.to_be_bytes();
    let mut out = vec![0u8; k.saturating_sub(bytes.len())];
    let skip = bytes.len().saturating_sub(k);
    out.extend_from_slice(bytes.get(skip..).unwrap_or_default());
    Ok(Some(out))
}

/// `DigestInfo ::= SEQUENCE { AlgorithmIdentifier, OCTET STRING }`.
fn digest_info(alg: DigestAlg, digest: &[u8], null_params: bool) -> Vec<u8> {
    let id = der::algorithm(alg.oid(), null_params.then(der::null).as_deref());
    der::seq(&[&id, &der::octets(digest)])
}

/// RSASSA-PKCS1-v1_5 as the field really has it: the standard DigestInfo (with a NULL
/// parameter), the same without the NULL (RFC 8017 §9.2 note 1: old signers omit it), or the bare
/// digest with no DigestInfo at all.
pub fn pkcs1_verify(n: &[u8], e: &[u8], alg: DigestAlg, digest: &[u8], sig: &[u8]) -> Result<bool, SignError> {
    let Some(em) = encoded_message(n, e, sig)? else { return Ok(false) };
    let k = em.len();
    Ok([digest_info(alg, digest, true), digest_info(alg, digest, false), digest.to_vec()].iter().any(|t| {
        let Some(ps) = k.checked_sub(t.len() + 3).filter(|ps| *ps >= 8) else { return false };
        let mut expected = vec![0x00, 0x01];
        expected.extend(std::iter::repeat_n(0xFF, ps));
        expected.push(0x00);
        expected.extend_from_slice(t);
        expected == em
    }))
}

/// MGF1 (RFC 8017 §B.2.1).
fn mgf1(hash: DigestAlg, seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + hash.output_len());
    let mut counter = 0u32;
    while out.len() < len {
        out.extend(hash.digest(&[seed, &counter.to_be_bytes()]));
        counter = counter.wrapping_add(1);
    }
    out.truncate(len);
    out
}

/// EMSA-PSS-VERIFY (RFC 8017 §9.1.2) with `digest` (of the message, with `alg`) as `mHash`.
pub fn pss_verify(n: &[u8], e: &[u8], alg: DigestAlg, params: PssParams, digest: &[u8], sig: &[u8]) -> Result<bool, SignError> {
    let Some(raw) = encoded_message(n, e, sig)? else { return Ok(false) };
    let mod_bits = n.first().map_or(0, |b| (n.len() * 8) as u32 - b.leading_zeros());
    let Some(em_bits) = mod_bits.checked_sub(1) else { return Ok(false) };
    let em_len = em_bits.div_ceil(8) as usize;
    // emLen is k, or k - 1 when the modulus is 8m+1 bits (then the top byte must be zero).
    let Some(lead) = raw.len().checked_sub(em_len) else { return Ok(false) };
    if raw.get(..lead).is_none_or(|l| l.iter().any(|b| *b != 0)) {
        return Ok(false);
    }
    let em = raw.get(lead..).unwrap_or_default();
    let h_len = alg.output_len();
    if digest.len() != h_len {
        return Ok(false);
    }
    let Some(db_len) = em_len.checked_sub(h_len + 1).filter(|l| *l >= 1) else { return Ok(false) };
    if em.last() != Some(&0xBC) {
        return Ok(false);
    }
    let (masked_db, rest) = em.split_at(db_len);
    let Some(h) = rest.get(..h_len) else { return Ok(false) };
    let spare = (8 * em_len as u32).saturating_sub(em_bits);
    let top_mask = 0xFFu8.checked_shr(spare).unwrap_or(0);
    if masked_db.first().is_none_or(|b| b & !top_mask != 0) {
        return Ok(false);
    }
    let mut db: Vec<u8> = masked_db.iter().zip(mgf1(params.mgf, h, db_len)).map(|(a, b)| a ^ b).collect();
    if let Some(b) = db.first_mut() {
        *b &= top_mask;
    }
    let Some(sep) = db.iter().position(|b| *b != 0) else { return Ok(false) };
    if db.get(sep) != Some(&1) {
        return Ok(false);
    }
    let salt = db.get(sep + 1..).unwrap_or_default();
    if params.salt_len.is_some_and(|l| l != salt.len()) {
        return Ok(false);
    }
    Ok(alg.digest(&[&[0u8; 8], digest, salt]) == h)
}
