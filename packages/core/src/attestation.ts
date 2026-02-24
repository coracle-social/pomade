import {decode, encode, Tag} from "cbor-x"
import * as x509 from "@peculiar/x509"

// The AWS Nitro Attestation root CA certificate (PEM), valid for 30 years.
// Source: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
// SHA256:  8cf60e2b2efca96c6a9e71e851d00c1b6991cc09eadbe64a6a1d1b1eb9faff7c
// Fingerprint: 64:1A:03:21:A3:E2:44:EF:E4:56:46:31:95:D6:06:31:7E:D7:CD:CC:3C:17:56:E0:98:93:F3:C6:8F:79:BB:5B
const NITRO_ROOT_CA_PEM = `-----BEGIN CERTIFICATE-----
MIICETCCAZagAwIBAgIRAPkxdWgbkK/hHUbMtOTn+FYwCgYIKoZIzj0EAwMwSTEL
MAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMRswGQYD
VQQDDBJhd3Mubml0cm8tZW5jbGF2ZXMwHhcNMTkxMDI4MTMyODA1WhcNNDkxMDI4
MTQyODA1WjBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQL
DANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczB2MBAGByqGSM49AgEG
BSuBBAAiA2IABPwCVOumCMHzaHDimtqQvkY4MpJzbolL//Zy2YlES1BR5TSksfbb
48C8WBoyt7F2Bw7eEtaaP+ohG2bnUs990d0JX28TcPQXCEPZ3BABIeTPYwEoCWZE
h8l5YoQwTcU/9KNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUkCW1DdkF
R+eWw5b6cp3PmanfS5YwDgYDVR0PAQH/BAQDAgGGMAoGCCqGSM49BAMDA2kAMGYC
MQCjfy+Rocm9Xue4YnwWmNJVA44fA0P5W2OpYow9OYCVRaEevL8uO1XYru5xtMPW
rfMCMQCi85sWBbJwKKXdS6BptQFuZbT73o/gBh1qUxl/nNr12UO8Yfwr6wPLb+6N
IwLz3/Y=
-----END CERTIFICATE-----`

export type AttestationDocument = {
  moduleId: string
  timestamp: number
  digest: string
  pcrs: Record<number, Uint8Array>
  certificate: Uint8Array
  cabundle: Uint8Array[]
  publicKey?: Uint8Array
  userData?: Uint8Array
  nonce?: Uint8Array
}

export type AttestationResult = {
  ok: boolean
  document?: AttestationDocument
  error?: string
}

/**
 * Validate a base64-encoded AWS Nitro attestation document.
 *
 * Steps:
 *   1. CBOR-decode the outer COSE_Sign1 structure (tagged or untagged).
 *   2. CBOR-decode the payload to extract the attestation document fields.
 *   3. Validate the certificate chain up to the hardcoded Nitro root CA.
 *   4. Verify the COSE_Sign1 ECDSA P-384 signature.
 *
 * Returns the parsed document on success so the caller can inspect PCR values.
 */
export async function validateAttestation(documentB64: string): Promise<AttestationResult> {
  try {
    const raw = base64ToBytes(documentB64)

    // 1. Decode the COSE_Sign1 structure — may be CBOR-tagged (tag 18)
    let decoded = decode(raw)
    if (decoded instanceof Tag) decoded = decoded.value

    if (!Array.isArray(decoded) || decoded.length !== 4) {
      return {ok: false, error: "Invalid COSE_Sign1 structure"}
    }

    const [protectedHeaderBytes, , payloadBytes, signature] = decoded as [
      Uint8Array,
      unknown,
      Uint8Array,
      Uint8Array,
    ]

    // 2. Decode the attestation document payload
    const raw_doc = decode(payloadBytes)

    const document: AttestationDocument = {
      moduleId: raw_doc.module_id,
      timestamp: Number(raw_doc.timestamp),
      digest: raw_doc.digest,
      pcrs: Object.fromEntries(
        Object.entries(raw_doc.pcrs as Record<number, Uint8Array>).map(([k, v]) => [Number(k), v]),
      ),
      certificate: raw_doc.certificate,
      cabundle: raw_doc.cabundle,
      publicKey: raw_doc.public_key,
      userData: raw_doc.user_data,
      nonce: raw_doc.nonce,
    }

    // 3. Validate the certificate chain
    const chainError = await validateCertChain(document.certificate, document.cabundle)
    if (chainError) return {ok: false, error: chainError}

    // 4. Verify the COSE_Sign1 signature
    const sigError = await verifyCoseSign1(
      protectedHeaderBytes,
      payloadBytes,
      signature,
      document.certificate,
    )
    if (sigError) return {ok: false, error: sigError}

    return {ok: true, document}
  } catch (e) {
    return {ok: false, error: String(e)}
  }
}

// ---------------------------------------------------------------------------
// Certificate chain validation
// ---------------------------------------------------------------------------

async function validateCertChain(
  leafDer: Uint8Array,
  cabundle: Uint8Array[],
): Promise<string | undefined> {
  // cabundle is ordered [ROOT, INTERM_1, ..., INTERM_N].
  // The chain to validate is [leaf, INTERM_N, ..., INTERM_1, ROOT].
  const chain = [leafDer, ...[...cabundle].reverse()]
  const certs = chain.map(der => new x509.X509Certificate(der))
  const root = new x509.X509Certificate(NITRO_ROOT_CA_PEM)

  const now = new Date()

  for (const cert of certs) {
    if (now < cert.notBefore || now > cert.notAfter) {
      return `Certificate expired or not yet valid: ${cert.subject}`
    }
  }

  // Verify each link in the chain: cert[i] signed by cert[i+1]
  for (let i = 0; i < certs.length - 1; i++) {
    const verified = await certs[i].verify({
      publicKey: certs[i + 1],
      signatureOnly: true,
    })
    if (!verified) {
      return `Certificate chain verification failed at index ${i}`
    }
  }

  // Verify the root of the bundle matches the hardcoded Nitro root CA
  const bundleRoot = certs[certs.length - 1]
  const rootVerified = await bundleRoot.verify({publicKey: root, signatureOnly: true})
  if (!rootVerified) {
    return "Root certificate does not match the AWS Nitro root CA"
  }

  return undefined
}

// ---------------------------------------------------------------------------
// COSE_Sign1 signature verification
// ---------------------------------------------------------------------------

async function verifyCoseSign1(
  protectedHeaderBytes: Uint8Array,
  payload: Uint8Array,
  signature: Uint8Array,
  leafDer: Uint8Array,
): Promise<string | undefined> {
  // Reconstruct the Sig_Structure that was signed:
  //   ["Signature1", protected_header_bytes, external_aad (empty bstr), payload]
  const sigStructure = encode(["Signature1", protectedHeaderBytes, new Uint8Array(0), payload])

  const cert = new x509.X509Certificate(leafDer)
  const cryptoKey = await cert.publicKey.export(crypto)

  const valid = await crypto.subtle.verify(
    {name: "ECDSA", hash: "SHA-384"},
    cryptoKey,
    signature,
    sigStructure,
  )

  return valid ? undefined : "COSE_Sign1 signature verification failed"
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function base64ToBytes(b64: string): Uint8Array {
  const binary = atob(b64)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes
}
