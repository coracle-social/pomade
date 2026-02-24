use aws_nitro_enclaves_nsm_api::api::{Request, Response};
use aws_nitro_enclaves_nsm_api::driver::{nsm_exit, nsm_init, nsm_process_request};
use serde_bytes::ByteBuf;

/// Request a signed attestation document from the Nitro Secure Module.
///
/// All three fields are optional user-supplied blobs that the NSM will embed
/// verbatim in the signed document, allowing callers to bind arbitrary data
/// (e.g. a nonce or ephemeral public key) to the enclave's identity.
///
/// Returns the raw CBOR-encoded attestation document on success.
pub fn get_attestation_doc(
    user_data: Option<Vec<u8>>,
    nonce: Option<Vec<u8>>,
    public_key: Option<Vec<u8>>,
) -> Result<Vec<u8>, String> {
    let fd = nsm_init();
    if fd < 0 {
        return Err("failed to open NSM device".into());
    }

    let request = Request::Attestation {
        user_data: user_data.map(ByteBuf::from),
        nonce: nonce.map(ByteBuf::from),
        public_key: public_key.map(ByteBuf::from),
    };

    let response = nsm_process_request(fd, request);
    nsm_exit(fd);

    match response {
        Response::Attestation { document } => Ok(document),
        Response::Error(e) => Err(format!("NSM error: {:?}", e)),
        _ => Err("unexpected NSM response".into()),
    }
}
