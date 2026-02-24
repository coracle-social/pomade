/// KMS-backed secret provisioning for Nitro Enclaves.
///
/// Flow per secret:
///   1. Generate an ephemeral RSA-2048 keypair inside the enclave.
///   2. Obtain an NSM attestation document embedding the ephemeral public key
///      (DER-encoded) so KMS can verify the caller is a genuine enclave.
///   3. Call KMS `Decrypt` with a `Recipient` block containing the attestation
///      document. KMS verifies the PCRs, then returns `CiphertextForRecipient`
///      — the plaintext encrypted under our ephemeral public key — instead of
///      raw plaintext, so the host operator never sees the secret.
///   4. Decrypt `CiphertextForRecipient` with the ephemeral private key using
///      RSA-OAEP-SHA-256 to recover the plaintext.
///
/// AWS credentials are fetched from the IMDSv2 endpoint on the parent instance
/// (reachable via the VSOCK-to-TCP proxy) and used to sign the KMS request with
/// SigV4.
use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{SignableBody, SignableRequest, SigningSettings, sign};
use aws_sigv4::sign::v4;
use base64::{Engine, engine::general_purpose::STANDARD};
use rsa::pkcs8::EncodePublicKey;
use rsa::rand_core::OsRng;
use rsa::{Oaep, RsaPrivateKey, RsaPublicKey};
use serde::Deserialize;

use crate::attestation::get_attestation_doc;

const IMDS_BASE: &str = "http://169.254.169.254";
const KMS_TARGET: &str = "TrentService.Decrypt";

// ---- IMDSv2 credentials ----

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ImdsCredentials {
    access_key_id: String,
    secret_access_key: String,
    token: String,
}

/// Fetch short-lived credentials from the IMDSv2 endpoint on the parent
/// instance. The parent's VSOCK-to-TCP proxy must forward traffic to
/// 169.254.169.254 for this to work.
pub async fn fetch_credentials(client: &reqwest::Client) -> Result<Credentials, String> {
    // Step 1: obtain a session token
    let token = client
        .put(format!("{IMDS_BASE}/latest/api/token"))
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send()
        .await
        .map_err(|e| format!("IMDS token request failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("IMDS token read failed: {e}"))?;

    // Step 2: discover the IAM role name attached to the instance
    let role = client
        .get(format!(
            "{IMDS_BASE}/latest/meta-data/iam/security-credentials/"
        ))
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .map_err(|e| format!("IMDS role request failed: {e}"))?
        .text()
        .await
        .map_err(|e| format!("IMDS role read failed: {e}"))?;

    let role = role.lines().next().unwrap_or("").trim().to_string();

    // Step 3: fetch the credentials for that role
    let creds: ImdsCredentials = client
        .get(format!(
            "{IMDS_BASE}/latest/meta-data/iam/security-credentials/{role}"
        ))
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await
        .map_err(|e| format!("IMDS credentials request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("IMDS credentials parse failed: {e}"))?;

    Ok(Credentials::new(
        creds.access_key_id,
        creds.secret_access_key,
        Some(creds.token),
        None,
        "imds",
    ))
}

// ---- KMS attestation-bound decrypt ----

/// Decrypt a KMS-encrypted ciphertext using Nitro attestation.
///
/// `ciphertext_b64` is the base64-encoded blob produced by `aws kms encrypt`
/// (or `GenerateDataKey`). `key_id` is the KMS key ARN or alias — for
/// symmetric keys it is embedded in the ciphertext and may be omitted, but
/// passing it explicitly is recommended as a best practice. `region` is the
/// AWS region string (e.g. `"us-east-1"`).
///
/// Returns the plaintext bytes.
pub async fn kms_decrypt(
    client: &reqwest::Client,
    ciphertext_b64: &str,
    key_id: Option<&str>,
    region: &str,
    credentials: &Credentials,
) -> Result<Vec<u8>, String> {
    // 1. Generate ephemeral RSA-2048 keypair
    let private_key =
        RsaPrivateKey::new(&mut OsRng, 2048).map_err(|e| format!("RSA keygen failed: {e}"))?;
    let public_key = RsaPublicKey::from(&private_key);
    let pub_der = public_key
        .to_public_key_der()
        .map_err(|e| format!("RSA DER encode failed: {e}"))?
        .to_vec();

    // 2. Get attestation document with the ephemeral public key embedded
    let attest_doc = get_attestation_doc(None, None, Some(pub_der))
        .map_err(|e| format!("attestation failed: {e}"))?;

    // 3. Build and sign the KMS Decrypt request
    let body = build_kms_request_body(ciphertext_b64, key_id, &attest_doc);
    let endpoint = format!("https://kms.{region}.amazonaws.com/");

    let mut request = reqwest::Request::new(
        reqwest::Method::POST,
        endpoint
            .parse()
            .map_err(|e| format!("URL parse failed: {e}"))?,
    );
    request.headers_mut().insert(
        "content-type",
        "application/x-amz-json-1.1".parse().unwrap(),
    );
    request
        .headers_mut()
        .insert("x-amz-target", KMS_TARGET.parse().unwrap());
    *request.body_mut() = Some(body.clone().into());

    sign_request(&mut request, &body, region, credentials)?;

    // 4. Send and parse the response
    let response = client
        .execute(request)
        .await
        .map_err(|e| format!("KMS request failed: {e}"))?;

    let status = response.status();
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|e| format!("KMS response parse failed: {e}"))?;

    if !status.is_success() {
        return Err(format!(
            "KMS error {status}: {}",
            body.get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("unknown")
        ));
    }

    let ciphertext_for_recipient = body
        .get("CiphertextForRecipient")
        .and_then(|v| v.as_str())
        .ok_or("KMS response missing CiphertextForRecipient")?;

    // 5. Decrypt CiphertextForRecipient with the ephemeral private key
    let encrypted = STANDARD
        .decode(ciphertext_for_recipient)
        .map_err(|e| format!("base64 decode of CiphertextForRecipient failed: {e}"))?;

    private_key
        .decrypt(Oaep::new::<sha2::Sha256>(), &encrypted)
        .map_err(|e| format!("RSA decrypt failed: {e}"))
}

// ---- Helpers ----

fn build_kms_request_body(ciphertext_b64: &str, key_id: Option<&str>, attest_doc: &[u8]) -> String {
    let mut body = serde_json::json!({
        "CiphertextBlob": ciphertext_b64,
        "Recipient": {
            "AttestationDocument": STANDARD.encode(attest_doc),
            "KeyEncryptionAlgorithm": "RSAES_OAEP_SHA_256"
        }
    });
    if let Some(id) = key_id {
        body["KeyId"] = serde_json::json!(id);
    }
    body.to_string()
}

fn sign_request(
    request: &mut reqwest::Request,
    body: &str,
    region: &str,
    credentials: &Credentials,
) -> Result<(), String> {
    let identity = credentials.clone().into();
    let signing_params = v4::SigningParams::builder()
        .identity(&identity)
        .region(region)
        .name("kms")
        .time(SystemTime::now())
        .settings(SigningSettings::default())
        .build()
        .map_err(|e| format!("signing params build failed: {e}"))?
        .into();

    let existing_headers: Vec<(String, String)> = request
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let signable = SignableRequest::new(
        request.method().as_str(),
        request.url().as_str(),
        existing_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str())),
        SignableBody::Bytes(body.as_bytes()),
    )
    .map_err(|e| format!("signable request failed: {e}"))?;

    let (instructions, _) = sign(signable, &signing_params)
        .map_err(|e| format!("signing failed: {e}"))?
        .into_parts();

    // Apply the signed headers (Authorization, x-amz-date, x-amz-security-token)
    // directly to the reqwest request without needing the `http` crate.
    for (name, value) in instructions.headers() {
        request.headers_mut().insert(
            reqwest::header::HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| format!("invalid header name: {e}"))?,
            value
                .parse()
                .map_err(|e| format!("invalid header value: {e}"))?,
        );
    }

    Ok(())
}
