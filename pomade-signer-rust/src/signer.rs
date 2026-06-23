#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use frost_taproot::commit::create_commit_pkg;
use frost_taproot::types::{SecretNonce, SecretShare};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;

use crate::nostr::{NostrAuth, parse_auth};
use crate::ratelimit::{
    RateLimitBucket, RateLimitConfig, get_rate_limit_reset_time, is_rate_limited, record_attempt,
};
use crate::schema::{
    Auth, ChallengeRequest, ChallengeResponse, EcdhRequest, EcdhResponse, Group, Hex32, Hex33,
    LoginSelectRequest, LoginSelectResponse, LoginStartRequest, LoginStartResponse,
    RecoverySelectRequest, RecoverySelectResponse, RecoverySetupRequest, RecoverySetupResponse,
    RecoveryStartRequest, RecoveryStartResponse, RegisterRequest, RegisterResponse,
    SessionDeactivateRequest, SessionDeactivateResponse, SessionDeleteRequest,
    SessionDeleteResponse, SessionItem, SessionListResponse, Share, SignCommitRequest,
    SignCommitResponse, SignCommitResult, SignCompleteRequest, SignCompleteResponse,
};
use crate::session::{create_ecdh_pkg, create_psig_pkg_with_nonce, is_group_member};
use crate::storage::{Collection, Storage, StorageBackend};

const GENERATOR_X: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

const CLIENT_RATE_LIMITS: RateLimitConfig = RateLimitConfig {
    max_attempts: 100,
    window_seconds: 60,
};

const EMAIL_RATE_LIMITS: RateLimitConfig = RateLimitConfig {
    max_attempts: 5,
    window_seconds: 120,
};

const MONTH_SECS: u64 = 30 * 24 * 3600;
const MINUTE_SECS: u64 = 60;

/// How long an unconsumed round-1 commitment lives before being reaped.
const COMMIT_TTL_SECS: u64 = 2 * 60;

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn random_int(min: u32, max: u32) -> u32 {
    let mut buf = [0u8; 4];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    let v = u32::from_be_bytes(buf);
    min + (v % (max - min))
}

/// Generate a fresh, globally-unique opaque commit id (32 random bytes, hex).
fn random_commit_id() -> String {
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Derive a compressed (33-byte) public key from a 32-byte secret.
fn get_pubkey_compressed(secret: &[u8; 32]) -> [u8; 33] {
    frost_taproot::helpers::get_pubkey(secret)
}

/// A pending round-1 commitment. The secret nonce lives in memory only and is
/// never serialized, logged, or returned to the client.
struct CommitEntry {
    commit_id: String,
    members: Vec<u32>,
    secret: SecretNonce,
    created_at: u64,
}

// ---- Domain types ----

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerSession {
    pub client: String,
    pub share: Share,
    pub group: Group,
    pub recovery: bool,
    pub created_at: u64,
    pub deactivated_at: Option<u64>,
    pub last_activity: u64,
    pub email: Option<String>,
    pub email_hash: Option<String>,
    pub password_hash: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SessionIndex {
    pub clients: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerRecovery {
    pub created_at: u64,
    pub clients: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerLogin {
    pub created_at: u64,
    pub clients: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignerChallenge {
    pub created_at: u64,
    pub otp: String,
}

pub struct ChallengePayload {
    pub email: String,
    pub otp: String,
}

const CHALLENGE_HTML: &str = include_str!("../challenge.html");

fn challenge_html(otp: &str) -> String {
    CHALLENGE_HTML.replace("{{otp}}", otp)
}

fn challenge_email(otp: &str) -> crate::mailer::Email {
    crate::mailer::Email {
        to: String::new(), // filled in by caller
        subject: "Your One-Time Password".into(),
        text: format!(
            "Someone attempted to log in using your email address. If this was you, please continue by copying the one-time password below:\n\n{}\n\nThis code will expire in 15 minutes.\n\nIf you did not request this code, please ignore this email.\n\n---\n\nThis is an automated message from a Nostr signer. Please do not reply to this email.",
            otp
        ),
        html: challenge_html(otp),
    }
}

fn make_session_item(session: &SignerSession) -> SessionItem {
    // group_pk is a 33-byte compressed point; strip the 02/03 prefix for the x-only pubkey
    let pubkey = session.group.group_pk.0[2..].to_string();
    SessionItem {
        pubkey: crate::schema::Hex32(pubkey),
        client: crate::schema::Hex32(session.client.clone()),
        created_at: session.created_at,
        deactivated_at: session.deactivated_at,
        last_activity: session.last_activity,
        threshold: session.group.threshold,
        total: session.group.commits.0.len() as u32,
        idx: session.share.idx,
        email: session.email.clone(),
    }
}

// ---- Signer ----

pub struct SignerOptions {
    pub url: String,
    pub register_pow: u32,
    pub argon_m: u32,
    pub from_email: String,
    pub from_name: String,
    pub mailer: Option<Box<dyn crate::mailer::Mailer>>,
    pub test_mode: bool,
}

pub struct Signer {
    options: SignerOptions,
    logins: Collection<SignerLogin>,
    sessions: Collection<SignerSession>,
    recoveries: Collection<SignerRecovery>,
    challenges: Collection<SignerChallenge>,
    sessions_by_email_hash: Collection<SessionIndex>,
    rate_limit_by_email_hash: Collection<RateLimitBucket>,
    rate_limit_by_client: Collection<RateLimitBucket>,
    commits_by_client: Mutex<HashMap<String, Vec<CommitEntry>>>,
}

impl Signer {
    pub fn open(options: SignerOptions, backend: impl StorageBackend) -> Self {
        let storage = Storage::new(backend);
        Self {
            logins: storage.collection("logins"),
            sessions: storage.collection("sessions"),
            recoveries: storage.collection("recoveries"),
            challenges: storage.collection("challenges"),
            sessions_by_email_hash: storage.collection("sessionsByEmailHash"),
            rate_limit_by_email_hash: storage.collection("rateLimitByEmailHash"),
            rate_limit_by_client: storage.collection("rateLimitByClient"),
            commits_by_client: Mutex::new(HashMap::new()),
            options,
        }
    }

    /// Clean up expired logins, recoveries, challenges, and rate limit buckets.
    pub fn cleanup(&self) {
        let cutoff_15m = now().saturating_sub(15 * MINUTE_SECS);
        let cutoff_month = now().saturating_sub(MONTH_SECS);

        for (k, r) in self.recoveries.entries() {
            if r.created_at < cutoff_15m {
                self.recoveries.delete(&k);
            }
        }
        for (k, l) in self.logins.entries() {
            if l.created_at < cutoff_15m {
                self.logins.delete(&k);
            }
        }
        for (k, c) in self.challenges.entries() {
            if c.created_at < cutoff_15m {
                self.challenges.delete(&k);
            }
        }
        for (k, b) in self.rate_limit_by_email_hash.entries() {
            if b.last_attempt < now().saturating_sub(EMAIL_RATE_LIMITS.window_seconds) {
                self.rate_limit_by_email_hash.delete(&k);
            }
        }
        for (k, b) in self.rate_limit_by_client.entries() {
            if b.last_attempt < now().saturating_sub(CLIENT_RATE_LIMITS.window_seconds) {
                self.rate_limit_by_client.delete(&k);
            }
        }
        for (k, s) in self.sessions.entries() {
            if s.last_activity < cutoff_month {
                self.sessions.delete(&k);
            }
        }

        let commit_cutoff = now().saturating_sub(COMMIT_TTL_SECS);
        let mut commits = self.commits_by_client.lock().unwrap();
        commits.retain(|_, pending| {
            pending.retain(|e| e.created_at >= commit_cutoff);
            !pending.is_empty()
        });
    }

    // ---- Internal helpers ----

    fn check_and_record_rate_limit(&self, client: &str) -> bool {
        let bucket = self.rate_limit_by_client.get(client);
        if is_rate_limited(bucket.as_ref(), &CLIENT_RATE_LIMITS) {
            let reset = get_rate_limit_reset_time(bucket.as_ref(), &CLIENT_RATE_LIMITS);
            log::debug!(
                "[signer]: rate limit exceeded for client {}, reset in {}s",
                &client[..8],
                reset
            );
            return false;
        }
        self.rate_limit_by_client.set(
            client,
            &record_attempt(bucket.as_ref(), &CLIENT_RATE_LIMITS),
        );
        true
    }

    /// Atomically consume the commitment for `commit_id` from `client`'s pending
    /// list, splicing it out under the lock. Returns the entry if present, else
    /// None. Scoping the lookup to the requesting client's own list structurally
    /// prevents consuming another client's commitment, and the single locked
    /// find-and-remove enforces single-use: concurrent completions for one
    /// commit_id yield at most one success.
    fn take_commit(&self, commit_id: &str, client: &str) -> Option<CommitEntry> {
        let mut commits = self.commits_by_client.lock().unwrap();
        let pending = commits.get_mut(client)?;
        let pos = pending
            .iter()
            .position(|e| ct_str_eq(&e.commit_id, commit_id))?;
        let entry = pending.swap_remove(pos);
        if pending.is_empty() {
            commits.remove(client);
        }
        Some(entry)
    }

    fn get_authenticated_sessions(&self, auth: &Auth) -> Vec<SignerSession> {
        let email_hash = auth.email_hash();
        let bucket = self.rate_limit_by_email_hash.get(email_hash);
        if is_rate_limited(bucket.as_ref(), &EMAIL_RATE_LIMITS) {
            let reset = get_rate_limit_reset_time(bucket.as_ref(), &EMAIL_RATE_LIMITS);
            log::debug!(
                "[signer]: rate limit exceeded for email_hash {}, reset in {}s",
                &email_hash[..8],
                reset
            );
            return vec![];
        }

        let index = self.sessions_by_email_hash.get(email_hash);
        let mut sessions: Vec<SignerSession> = vec![];

        if let Some(index) = &index {
            match auth {
                Auth::Password(pa) => {
                    sessions = index
                        .clients
                        .iter()
                        .filter_map(|c| self.sessions.get(c))
                        .filter(|s| {
                            s.password_hash
                                .as_deref()
                                .is_some_and(|h| ct_str_eq(h, &pa.password_hash))
                        })
                        .collect();
                }
                Auth::Otp(oa) => {
                    if let Some(challenge) = self.challenges.get(email_hash) {
                        self.challenges.delete(email_hash);
                        if ct_str_eq(&oa.otp, &challenge.otp) {
                            sessions = index
                                .clients
                                .iter()
                                .filter_map(|c| self.sessions.get(c))
                                .collect();
                        }
                    }
                }
            }
        }

        if sessions.is_empty() {
            self.rate_limit_by_email_hash.set(
                email_hash,
                &record_attempt(bucket.as_ref(), &EMAIL_RATE_LIMITS),
            );
        }

        sessions
    }

    fn check_key_reuse(&self, client: &str) -> bool {
        if self.sessions.get(client).is_some() {
            log::debug!("[client {}]: session key re-used", &client[..8]);
            return true;
        }
        if self.recoveries.get(client).is_some() {
            log::debug!("[client {}]: recovery key re-used", &client[..8]);
            return true;
        }
        if self.logins.get(client).is_some() {
            log::debug!("[client {}]: login key re-used", &client[..8]);
            return true;
        }
        false
    }

    fn add_session(&self, client: &str, session: SignerSession) {
        self.sessions.set(client, &session);
        if let Some(email_hash) = &session.email_hash {
            let mut index = self
                .sessions_by_email_hash
                .get(email_hash)
                .unwrap_or(SessionIndex { clients: vec![] });
            if !index.clients.contains(&client.to_string()) {
                index.clients.push(client.to_string());
            }
            self.sessions_by_email_hash.set(email_hash, &index);
        }
    }

    fn deactivate_session(&self, client: &str) {
        if let Some(session) = self.sessions.get(client) {
            self.sessions.set(
                client,
                &SignerSession {
                    deactivated_at: Some(now()),
                    ..session
                },
            );
        }
    }

    fn delete_session(&self, client: &str) {
        if let Some(session) = self.sessions.get(client) {
            if let Some(email_hash) = &session.email_hash
                && let Some(mut index) = self.sessions_by_email_hash.get(email_hash)
            {
                index.clients.retain(|c| c != client);
                if index.clients.is_empty() {
                    self.sessions_by_email_hash.delete(email_hash);
                } else {
                    self.sessions_by_email_hash.set(email_hash, &index);
                }
            }
            self.sessions.delete(client);
        }
    }

    // ---- Handlers ----

    fn handle_register(&self, auth: &NostrAuth, data: RegisterRequest) -> RegisterResponse {
        let client = &auth.pubkey;
        let RegisterRequest {
            group,
            share,
            recovery,
        } = data;

        if self.check_key_reuse(client) {
            return RegisterResponse {
                ok: false,
                message: "Do not re-use session keys.".into(),
            };
        }

        if crate::pow::get_pow(auth.event.id.as_bytes()) < self.options.register_pow {
            log::debug!("[client {}]: insufficient proof of work", &client[..8]);
            return RegisterResponse {
                ok: false,
                message: "Registration requires 16 bits of proof of work (NIP-13).".into(),
            };
        }

        let threshold = group.threshold as usize;
        let total = group.commits.0.len();
        if threshold == 0 || threshold > total {
            log::debug!("[client {}]: invalid group threshold", &client[..8]);
            return RegisterResponse {
                ok: false,
                message: "Invalid group threshold.".into(),
            };
        }

        if !is_group_member(&group, &share) {
            log::debug!(
                "[client {}]: share does not belong to the provided group",
                &client[..8]
            );
            return RegisterResponse {
                ok: false,
                message: "Share does not belong to the provided group.".into(),
            };
        }

        let mut idxs: Vec<u32> = group.commits.0.iter().map(|c| c.idx).collect();
        let orig_len = idxs.len();
        idxs.dedup();
        if idxs.len() != orig_len {
            log::debug!(
                "[client {}]: group contains duplicate member indices",
                &client[..8]
            );
            return RegisterResponse {
                ok: false,
                message: "Group contains duplicate member indices.".into(),
            };
        }

        if !group.commits.0.iter().any(|c| c.idx == share.idx) {
            log::debug!(
                "[client {}]: share index not found in group commits",
                &client[..8]
            );
            return RegisterResponse {
                ok: false,
                message: "Share index not found in group commits.".into(),
            };
        }

        if self.sessions.get(client).is_some() {
            log::debug!("[client {}]: client is already registered", &client[..8]);
            return RegisterResponse {
                ok: false,
                message: "Client is already registered.".into(),
            };
        }

        self.add_session(
            client,
            SignerSession {
                client: client.clone(),
                share,
                group,
                recovery,
                created_at: now(),
                deactivated_at: None,
                last_activity: now(),
                email: None,
                email_hash: None,
                password_hash: None,
            },
        );

        log::debug!("[client {}]: registered", &client[..8]);
        RegisterResponse {
            ok: true,
            message: "Your key has been registered".into(),
        }
    }

    fn handle_recovery_setup(
        &self,
        auth: &NostrAuth,
        data: RecoverySetupRequest,
    ) -> RecoverySetupResponse {
        let client = &auth.pubkey;
        let Some(session) = self.sessions.get(client) else {
            log::debug!(
                "[client {}]: no session found for recovery setup",
                &client[..8]
            );
            return RecoverySetupResponse {
                ok: false,
                message: "No session found.".into(),
            };
        };

        if !session.recovery {
            return RecoverySetupResponse {
                ok: false,
                message: "Recovery is disabled on this session.".into(),
            };
        }
        if session.created_at < now().saturating_sub(15 * MINUTE_SECS) {
            return RecoverySetupResponse {
                ok: false,
                message: "Recovery method must be set within 15 minutes of session.".into(),
            };
        }
        if session.email.is_some() {
            return RecoverySetupResponse {
                ok: false,
                message: "Recovery has already been initialized.".into(),
            };
        }

        let pw_re = regex_is_hex64(&data.password_hash);
        if !pw_re {
            return RecoverySetupResponse {
                ok: false,
                message: "Recovery method password hash must be an argon2id hash of user email and password.".into(),
            };
        }

        let email_hash = hash_email(&data.email, &self.options.url, self.options.argon_m);

        self.add_session(
            client,
            SignerSession {
                last_activity: now(),
                email: Some(data.email),
                email_hash: Some(email_hash.clone()),
                password_hash: Some(data.password_hash),
                ..session
            },
        );

        log::debug!(
            "[client {}]: recovery method initialized {}",
            &client[..8],
            &email_hash[..8]
        );
        RecoverySetupResponse {
            ok: true,
            message: "Recovery method successfully initialized.".into(),
        }
    }

    fn handle_challenge(&self, _auth: &NostrAuth, data: ChallengeRequest) -> ChallengeResponse {
        let bucket = self.rate_limit_by_email_hash.get(&data.email_hash);
        if is_rate_limited(bucket.as_ref(), &EMAIL_RATE_LIMITS) {
            return ChallengeResponse {
                ok: true,
                message: "Please check your email inbox for a one-time password.".into(),
            };
        }

        if let Some(index) = self.sessions_by_email_hash.get(&data.email_hash)
            && let Some(client) = index.clients.first()
            && let Some(session) = self.sessions.get(client)
            && let Some(email) = &session.email
        {
            self.rate_limit_by_email_hash.set(
                &data.email_hash,
                &record_attempt(bucket.as_ref(), &EMAIL_RATE_LIMITS),
            );
            let otp = format!("{}{}", data.prefix, random_int(100000, 1000000));
            self.challenges.set(
                &data.email_hash,
                &SignerChallenge {
                    otp: otp.clone(),
                    created_at: now(),
                },
            );
            if self.options.test_mode {
                log::info!("[challenge] otp={} to={}", otp, email);
            } else if let Some(mailer) = &self.options.mailer {
                let mut mail = challenge_email(&otp);
                mail.to = email.clone();
                let fut = mailer.send(&self.options.from_email, &self.options.from_name, mail);
                tokio::spawn(async move {
                    match tokio::time::timeout(std::time::Duration::from_secs(30), fut).await {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => log::error!("[challenge]: mail send failed: {}", e),
                        Err(_) => log::error!("[challenge]: mail send timed out"),
                    }
                });
            } else {
                panic!("mailer is required when test mode is disabled");
            }
            log::debug!("[challenge]: sent for {}", &data.email_hash);
        } else {
            log::debug!(
                "[challenge]: no session found for {}",
                &data.email_hash[..8]
            );
        }

        ChallengeResponse {
            ok: true,
            message: "Please check your email inbox for a one-time password.".into(),
        }
    }

    fn handle_recovery_start(
        &self,
        auth: &NostrAuth,
        data: RecoveryStartRequest,
    ) -> RecoveryStartResponse {
        let client = &auth.pubkey;
        if self.check_key_reuse(client) {
            return RecoveryStartResponse {
                ok: false,
                message: "Do not re-use session keys.".into(),
                items: None,
            };
        }

        let sessions = self.get_authenticated_sessions(&data.auth);
        if sessions.is_empty() {
            log::debug!("[client {}]: no sessions found for recovery", &client[..8]);
            return RecoveryStartResponse {
                ok: false,
                message: "No sessions found.".into(),
                items: None,
            };
        }

        let clients: Vec<String> = sessions.iter().map(|s| s.client.clone()).collect();
        let items: Vec<SessionItem> = sessions.iter().map(make_session_item).collect();
        self.recoveries.set(
            client,
            &SignerRecovery {
                created_at: now(),
                clients,
            },
        );

        log::debug!("[client {}]: sending recovery options", &client[..8]);
        RecoveryStartResponse {
            ok: true,
            message: "Successfully retrieved recovery options.".into(),
            items: Some(items),
        }
    }

    fn handle_recovery_select(
        &self,
        auth: &NostrAuth,
        data: RecoverySelectRequest,
    ) -> RecoverySelectResponse {
        let client = &auth.pubkey;
        let Some(recovery) = self.recoveries.get(client) else {
            log::debug!("[client {}]: no active recovery found", &client[..8]);
            return RecoverySelectResponse {
                ok: false,
                message: "No active recovery found.".into(),
                share: None,
                group: None,
            };
        };

        self.recoveries.delete(client);

        if !recovery.clients.contains(&data.client.0) {
            log::debug!(
                "[client {}]: invalid session selected for recovery",
                &client[..8]
            );
            return RecoverySelectResponse {
                ok: false,
                message: "Invalid session selected for recovery.".into(),
                share: None,
                group: None,
            };
        }

        let Some(session) = self.sessions.get(&data.client.0) else {
            log::debug!("[client {}]: recovery session not found", &client[..8]);
            return RecoverySelectResponse {
                ok: false,
                message: "Recovery session not found.".into(),
                share: None,
                group: None,
            };
        };

        log::debug!("[client {}]: recovery successfully completed", &client[..8]);
        RecoverySelectResponse {
            ok: true,
            message: "Recovery successfully completed.".into(),
            group: Some(session.group),
            share: Some(session.share),
        }
    }

    fn handle_login_start(&self, auth: &NostrAuth, data: LoginStartRequest) -> LoginStartResponse {
        let client = &auth.pubkey;
        if self.check_key_reuse(client) {
            return LoginStartResponse {
                ok: false,
                message: "Do not re-use session keys.".into(),
                items: None,
            };
        }

        let sessions = self.get_authenticated_sessions(&data.auth);
        if sessions.is_empty() {
            log::debug!("[client {}]: no sessions found for login", &client[..8]);
            return LoginStartResponse {
                ok: false,
                message: "No sessions found.".into(),
                items: None,
            };
        }

        let clients: Vec<String> = sessions.iter().map(|s| s.client.clone()).collect();
        let items: Vec<SessionItem> = sessions.iter().map(make_session_item).collect();
        self.logins.set(
            client,
            &SignerLogin {
                created_at: now(),
                clients,
            },
        );

        log::debug!("[client {}]: sending login options", &client[..8]);
        LoginStartResponse {
            ok: true,
            message: "Successfully retrieved login options.".into(),
            items: Some(items),
        }
    }

    fn handle_login_select(
        &self,
        auth: &NostrAuth,
        data: LoginSelectRequest,
    ) -> LoginSelectResponse {
        let client = &auth.pubkey;
        let Some(login) = self.logins.get(client) else {
            log::debug!("[client {}]: no active login found", &client[..8]);
            return LoginSelectResponse {
                ok: false,
                message: "No active login found.".into(),
                group: None,
            };
        };

        self.logins.delete(client);

        if !login.clients.contains(&data.client.0) {
            log::debug!(
                "[client {}]: invalid session selected for login",
                &client[..8]
            );
            return LoginSelectResponse {
                ok: false,
                message: "Invalid session selected for login.".into(),
                group: None,
            };
        }

        let Some(session) = self.sessions.get(&data.client.0) else {
            log::debug!("[client {}]: login session not found", &client[..8]);
            return LoginSelectResponse {
                ok: false,
                message: "Login session not found.".into(),
                group: None,
            };
        };

        let group = session.group.clone();
        self.add_session(
            client,
            SignerSession {
                client: client.clone(),
                share: session.share.clone(),
                group: session.group.clone(),
                email: session.email.clone(),
                email_hash: session.email_hash.clone(),
                password_hash: session.password_hash.clone(),
                recovery: true,
                created_at: now(),
                deactivated_at: None,
                last_activity: now(),
            },
        );

        log::debug!("[client {}]: login successfully completed", &client[..8]);
        LoginSelectResponse {
            ok: true,
            message: "Login successfully completed.".into(),
            group: Some(group),
        }
    }

    fn handle_sign_commit(&self, auth: &NostrAuth, data: SignCommitRequest) -> SignCommitResponse {
        let client = &auth.pubkey;
        let Some(session) = self.sessions.get(client) else {
            log::debug!(
                "[client {}]: commit failed - no session found",
                &client[..8]
            );
            return SignCommitResponse {
                ok: false,
                message: "No session found for client".into(),
                result: None,
            };
        };

        if session.deactivated_at.is_some() {
            return SignCommitResponse {
                ok: false,
                message: "Session is deactivated".into(),
                result: None,
            };
        }

        if !self.check_and_record_rate_limit(client) {
            return SignCommitResponse {
                ok: false,
                message: "Rate limit exceeded. Please try again later.".into(),
                result: None,
            };
        }

        if !data.members.0.contains(&session.share.idx) {
            return SignCommitResponse {
                ok: false,
                message: "Signer index not present in members list".into(),
                result: None,
            };
        }

        let Some(seckey) = hex::decode(&session.share.seckey.0)
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return SignCommitResponse {
                ok: false,
                message: "Failed to create commitment".into(),
                result: None,
            };
        };

        let secret_share = SecretShare {
            idx: session.share.idx,
            seckey,
        };
        let pkg = create_commit_pkg(&secret_share, None, None);
        let commit_id = random_commit_id();

        {
            let mut commits = self.commits_by_client.lock().unwrap();
            let pending = commits.entry(client.clone()).or_default();
            pending.push(CommitEntry {
                commit_id: commit_id.clone(),
                members: data.members.0.clone(),
                secret: pkg.secret_nonce(),
                created_at: now(),
            });
        }

        log::debug!("[client {}]: commitment created", &client[..8]);
        SignCommitResponse {
            ok: true,
            message: "Commitment created".into(),
            result: Some(SignCommitResult {
                commit_id: Hex32(commit_id),
                idx: session.share.idx,
                pubkey: Hex33(hex::encode(get_pubkey_compressed(&seckey))),
                hidden_pn: Hex33(hex::encode(pkg.hidden_pn)),
                binder_pn: Hex33(hex::encode(pkg.binder_pn)),
            }),
        }
    }

    fn handle_sign_complete(
        &self,
        auth: &NostrAuth,
        data: SignCompleteRequest,
    ) -> SignCompleteResponse {
        let client = &auth.pubkey;
        let Some(session) = self.sessions.get(client) else {
            log::debug!(
                "[client {}]: complete failed - no session found",
                &client[..8]
            );
            return SignCompleteResponse {
                ok: false,
                message: "No session found for client".into(),
                result: None,
            };
        };

        if session.deactivated_at.is_some() {
            return SignCompleteResponse {
                ok: false,
                message: "Session is deactivated".into(),
                result: None,
            };
        }

        if !self.check_and_record_rate_limit(client) {
            return SignCompleteResponse {
                ok: false,
                message: "Rate limit exceeded. Please try again later.".into(),
                result: None,
            };
        }

        // Atomically consume the commitment before doing any work. A second
        // completion for the same commit_id finds nothing and is refused.
        let Some(entry) = self.take_commit(&data.commit_id.0, client) else {
            log::debug!(
                "[client {}]: complete failed - commitment not found or already used",
                &client[..8]
            );
            return SignCompleteResponse {
                ok: false,
                message: "Commitment not found or already used".into(),
                result: None,
            };
        };

        // The completion's member set must match the one committed in round 1.
        if data.request.members.0 != entry.members {
            return SignCompleteResponse {
                ok: false,
                message: "Member set does not match commitment".into(),
                result: None,
            };
        }

        // pnonces must cover exactly the chosen member set, one entry each.
        let members = &data.request.members.0;
        let pnonces = &data.pnonces.0;
        let group_idxs: Vec<u32> = session.group.commits.0.iter().map(|c| c.idx).collect();
        let pnonces_valid = pnonces.len() == members.len()
            && members.iter().all(|m| {
                group_idxs.contains(m) && pnonces.iter().filter(|pn| pn.idx == *m).count() == 1
            });
        if !pnonces_valid {
            return SignCompleteResponse {
                ok: false,
                message: "Invalid public nonce set".into(),
                result: None,
            };
        }

        // The pnonce for this signer must equal the public half of the stored
        // fresh secret, binding round 2 to round 1 and blocking nonce substitution.
        let own_hidden = hex::encode(get_pubkey_compressed(&entry.secret.hidden_sn));
        let own_binder = hex::encode(get_pubkey_compressed(&entry.secret.binder_sn));
        let own_matches = pnonces.iter().any(|pn| {
            pn.idx == entry.secret.idx
                && pn.hidden_pn.0 == own_hidden
                && pn.binder_pn.0 == own_binder
        });
        if !own_matches {
            return SignCompleteResponse {
                ok: false,
                message: "Public nonce does not match commitment".into(),
                result: None,
            };
        }

        // The request carries a single `hash`; sid is computed over [hash],
        // byte-identical to the one-message session the client/bifrost computed.
        if !crate::session::verify_session_pkg(&session.group, &data.request) {
            return SignCompleteResponse {
                ok: false,
                message: "Failed to verify session package".into(),
                result: None,
            };
        }

        match create_psig_pkg_with_nonce(
            &session.group,
            &data.request,
            &session.share,
            &entry.secret,
            pnonces,
        ) {
            Ok(result) => {
                self.sessions.set(
                    client,
                    &SignerSession {
                        last_activity: now(),
                        ..session
                    },
                );
                log::debug!("[client {}]: signing complete", &client[..8]);
                SignCompleteResponse {
                    ok: true,
                    message: "Successfully signed event".into(),
                    result: Some(result),
                }
            }
            Err(e) => {
                log::debug!("[client {}]: complete failed - {}", &client[..8], e);
                SignCompleteResponse {
                    ok: false,
                    message: "Failed to sign event".into(),
                    result: None,
                }
            }
        }
    }

    fn handle_ecdh(&self, auth: &NostrAuth, data: EcdhRequest) -> EcdhResponse {
        let client = &auth.pubkey;
        let Some(session) = self.sessions.get(client) else {
            log::debug!("[client {}]: ecdh failed - no session found", &client[..8]);
            return EcdhResponse {
                ok: false,
                message: "No session found for client".into(),
                result: None,
            };
        };

        if session.deactivated_at.is_some() {
            log::debug!(
                "[client {}]: ecdh failed - session is deactivated",
                &client[..8]
            );
            return EcdhResponse {
                ok: false,
                message: "Session is deactivated".into(),
                result: None,
            };
        }

        if !self.check_and_record_rate_limit(client) {
            return EcdhResponse {
                ok: false,
                message: "Rate limit exceeded. Please try again later.".into(),
                result: None,
            };
        }

        if data.ecdh_pk.0 == GENERATOR_X {
            return EcdhResponse {
                ok: false,
                message: "Invalid ECDH public key".into(),
                result: None,
            };
        }

        match create_ecdh_pkg(&data, &session.share) {
            Ok(result) => {
                self.sessions.set(
                    client,
                    &SignerSession {
                        last_activity: now(),
                        ..session
                    },
                );
                log::debug!("[client {}]: ecdh complete", &client[..8]);
                EcdhResponse {
                    ok: true,
                    message: "Successfully derived shared secret".into(),
                    result: Some(result),
                }
            }
            Err(e) => {
                log::debug!("[client {}]: ecdh failed - {}", &client[..8], e);
                EcdhResponse {
                    ok: false,
                    message: "Key derivation failed".into(),
                    result: None,
                }
            }
        }
    }

    fn handle_session_list(&self, auth: &NostrAuth) -> SessionListResponse {
        let pubkey = &auth.pubkey;
        let items: Vec<SessionItem> = self
            .sessions
            .entries()
            .into_iter()
            .filter_map(|(_, s)| {
                if s.group.group_pk.0[2..] == *pubkey {
                    Some(make_session_item(&s))
                } else {
                    None
                }
            })
            .collect();

        log::debug!(
            "[session/list]: successfully retrieved {} sessions",
            items.len()
        );
        SessionListResponse {
            ok: true,
            message: "Successfully retrieved session list.".into(),
            items,
        }
    }

    fn handle_session_deactivate(
        &self,
        auth: &NostrAuth,
        data: SessionDeactivateRequest,
    ) -> SessionDeactivateResponse {
        let pubkey = &auth.pubkey;
        if let Some(session) = self.sessions.get(&data.client.0)
            && session.group.group_pk.0[2..] == *pubkey
        {
            self.deactivate_session(&data.client.0);
            log::debug!(
                "[session/deactivate]: deactivated session {}",
                &data.client.0[..8]
            );
            return SessionDeactivateResponse {
                ok: true,
                message: "Successfully deactivated selected session.".into(),
            };
        }
        log::debug!(
            "[session/deactivate]: failed to deactivate session {}",
            &data.client.0[..8]
        );
        SessionDeactivateResponse {
            ok: false,
            message: "Failed to deactivate selected session.".into(),
        }
    }

    fn handle_session_delete(
        &self,
        auth: &NostrAuth,
        data: SessionDeleteRequest,
    ) -> SessionDeleteResponse {
        let pubkey = &auth.pubkey;
        if let Some(session) = self.sessions.get(&data.client.0)
            && session.group.group_pk.0[2..] == *pubkey
        {
            self.delete_session(&data.client.0);
            log::debug!("[session/delete]: deleted session {}", &data.client.0[..8]);
            return SessionDeleteResponse {
                ok: true,
                message: "Successfully deleted selected session.".into(),
            };
        }
        log::debug!(
            "[session/delete]: failed to delete session {}",
            &data.client.0[..8]
        );
        SessionDeleteResponse {
            ok: false,
            message: "Failed to delete selected session.".into(),
        }
    }

    // ---- Routing ----

    pub fn handle(&self, path: &str, auth_header: &str, body: &Value) -> Value {
        let Some(auth) = parse_auth(auth_header, &self.options.url, path) else {
            log::debug!("[path]: failed to validate authentication");
            return serde_json::json!({"ok": false, "message": "Failed to validate authentication."});
        };

        macro_rules! route {
            ($schema:expr, $handler:expr) => {{
                match serde_json::from_value($schema.clone()) {
                    Ok(data) => serde_json::to_value($handler(&auth, data)).unwrap(),
                    Err(e) => {
                        log::debug!("[route]: failed to validate request body: {}", e);
                        serde_json::json!({"ok": false, "message": "Failed to validate request data."})
                    }
                }
            }};
        }

        match path {
            "/challenge" => route!(body, |a, d| self.handle_challenge(a, d)),
            "/ecdh" => route!(body, |a, d| self.handle_ecdh(a, d)),
            "/login/select" => route!(body, |a, d| self.handle_login_select(a, d)),
            "/login/start" => route!(body, |a, d| self.handle_login_start(a, d)),
            "/recovery/select" => route!(body, |a, d| self.handle_recovery_select(a, d)),
            "/recovery/setup" => route!(body, |a, d| self.handle_recovery_setup(a, d)),
            "/recovery/start" => route!(body, |a, d| self.handle_recovery_start(a, d)),
            "/register" => route!(body, |a, d| self.handle_register(a, d)),
            "/session/deactivate" => route!(body, |a, d| self.handle_session_deactivate(a, d)),
            "/session/delete" => route!(body, |a, d| self.handle_session_delete(a, d)),
            "/session/list" => {
                if !body.is_object() {
                    serde_json::json!({"ok": false, "message": "Failed to validate request data."})
                } else {
                    serde_json::to_value(self.handle_session_list(&auth)).unwrap()
                }
            }
            "/sign/commit" => route!(body, |a, d| self.handle_sign_commit(a, d)),
            "/sign/complete" => route!(body, |a, d| self.handle_sign_complete(a, d)),
            _ => serde_json::json!({"ok": false, "message": "Not found"}),
        }
    }
}

// ---- Utilities ----

fn hex_to_id(hex: &str) -> [u8; 32] {
    let b = hex::decode(hex).unwrap_or_default();
    b.try_into().unwrap_or([0u8; 32])
}

fn regex_is_hex64(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// Compare two strings in constant time with respect to their contents.
///
/// `subtle`'s `ct_eq` requires equal-length slices to avoid leaking content,
/// so unequal lengths short-circuit to `false`. Length is not the secret here
/// (these are fixed-length hashes / capability tokens); the byte contents are.
fn ct_str_eq(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.as_bytes().ct_eq(b.as_bytes()).into()
}

fn hash_email(email: &str, url: &str, argon_m: u32) -> String {
    use argon2::{Argon2, Params, Version};

    let params = Params::new(argon_m, 3, 2, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; 32];
    argon2
        .hash_password_into(email.as_bytes(), url.as_bytes(), &mut output)
        .expect("argon2 hash failed");

    hex::encode(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{BoundedVec, Commit, Group, Hex32, Hex33, Share};
    use crate::storage::SledBackend;
    use tempfile::TempDir;

    fn create_test_backend() -> (SledBackend, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let backend = SledBackend::open(temp_dir.path().join("test.db")).unwrap();
        (backend, temp_dir)
    }

    fn create_test_signer_options() -> SignerOptions {
        SignerOptions {
            url: "http://localhost:3000".to_string(),
            register_pow: 0,
            argon_m: 1024,
            from_email: "test@example.com".to_string(),
            from_name: "Test Signer".to_string(),
            mailer: None,
            test_mode: true,
        }
    }

    fn create_test_commit(idx: u32) -> Commit {
        Commit {
            idx,
            pubkey: Hex33("02".to_string() + &"a".repeat(64)),
            hidden_pn: Hex33("02".to_string() + &"b".repeat(64)),
            binder_pn: Hex33("02".to_string() + &"c".repeat(64)),
        }
    }

    fn create_test_group(threshold: u32, total: usize) -> Group {
        let commits: Vec<Commit> = (0..total).map(|i| create_test_commit(i as u32)).collect();
        Group {
            commits: BoundedVec(commits),
            group_pk: Hex33("02".to_string() + &"d".repeat(64)),
            threshold,
        }
    }

    fn create_test_share(idx: u32) -> Share {
        Share {
            idx,
            seckey: Hex32("1".repeat(64)),
        }
    }

    fn create_test_nostr_auth(pubkey: &str) -> NostrAuth {
        use nostr::util::JsonUtil;
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Build a minimal event JSON; signature is not verified in unit tests
        let event_json = format!(
            r#"{{"id":"{id}","pubkey":"{pubkey}","created_at":{now},"kind":27235,"tags":[["u","http://localhost:3000/test"],["method","POST"]],"content":"","sig":"{sig}"}}"#,
            id = "a".repeat(64),
            pubkey = pubkey,
            now = now,
            sig = "b".repeat(128),
        );
        let event = nostr::Event::from_json(event_json).expect("valid test event json");

        NostrAuth {
            pubkey: pubkey.to_string(),
            event,
        }
    }

    #[test]
    fn test_hash_email() {
        let email = "test@example.com";
        let url = "http://localhost:3002";
        let hash = hash_email(email, url, 1024);

        assert_eq!(hash.len(), 64);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));

        let hash2 = hash_email(email, url, 1024);
        assert_eq!(hash, hash2);

        let hash3 = hash_email(email, "http://localhost:3003", 1024);
        assert_ne!(hash, hash3);

        let hash4 = hash_email("other@example.com", url, 1024);
        assert_ne!(hash, hash4);
    }

    #[test]
    fn test_hex_to_id() {
        let hex = "a".repeat(64);
        let id = hex_to_id(&hex);
        assert_eq!(id.len(), 32);
        assert_eq!(hex::encode(id), hex);

        // Invalid hex should return zeros
        let invalid = hex_to_id("invalid");
        assert_eq!(invalid, [0u8; 32]);

        // Wrong length should be padded/truncated
        let short = hex_to_id("aa");
        assert_eq!(short.len(), 32);
    }

    #[test]
    fn test_regex_is_hex64() {
        assert!(regex_is_hex64(&"a".repeat(64)));
        assert!(regex_is_hex64(&"0".repeat(64)));
        assert!(regex_is_hex64(&"f".repeat(64)));
        assert!(regex_is_hex64("0123456789abcdef".repeat(4).as_str()));

        assert!(!regex_is_hex64(&"a".repeat(63))); // Too short
        assert!(!regex_is_hex64(&"a".repeat(65))); // Too long
        assert!(!regex_is_hex64("g".repeat(64).as_str())); // Invalid char
        assert!(!regex_is_hex64("ABCDEF".repeat(11).as_str())); // Uppercase
        assert!(!regex_is_hex64(""));
    }

    #[test]
    fn test_now() {
        let t1 = now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let t2 = now();
        assert!(t2 >= t1);
        assert!(t1 > 1_700_000_000); // Should be after 2023
    }

    #[test]
    fn test_random_int() {
        let r1 = random_int(100, 200);
        assert!((100..200).contains(&r1));

        let r2 = random_int(0, 1_000_000);
        assert!(r2 < 1_000_000);

        // Should produce different values (with high probability)
        let r3 = random_int(0, 1_000_000);
        let r4 = random_int(0, 1_000_000);
        // Not guaranteed, but extremely likely - just verify it runs
        let _ = (r3, r4);
    }

    #[test]
    fn test_signer_open() {
        let (storage, _temp) = create_test_backend();
        let options = create_test_signer_options();
        let _signer = Signer::open(options, storage);
    }

    #[test]
    fn test_check_key_reuse() {
        let (storage, _temp) = create_test_backend();
        let options = create_test_signer_options();
        let signer = Signer::open(options, storage);

        let client = "test_client_key";
        assert!(!signer.check_key_reuse(client));

        // Add a session
        let session = SignerSession {
            client: client.to_string(),
            share: create_test_share(0),
            group: create_test_group(1, 2),
            recovery: true,
            created_at: now(),
            deactivated_at: None,
            last_activity: now(),
            email: None,
            email_hash: None,
            password_hash: None,
        };
        signer.add_session(client, session);

        // Now it should be detected as reused
        assert!(signer.check_key_reuse(client));
    }

    #[test]
    fn test_add_and_get_session() {
        let (storage, _temp) = create_test_backend();
        let options = create_test_signer_options();
        let signer = Signer::open(options, storage);

        let client = "test_client";
        let session = SignerSession {
            client: client.to_string(),
            share: create_test_share(0),
            group: create_test_group(1, 2),
            recovery: true,
            created_at: now(),
            deactivated_at: None,
            last_activity: now(),
            email: Some("test@example.com".to_string()),
            email_hash: Some("hash123".to_string()),
            password_hash: Some("pw_hash".to_string()),
        };

        signer.add_session(client, session.clone());
        let retrieved = signer.sessions.get(client);

        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.client, client);
        assert_eq!(retrieved.email, Some("test@example.com".to_string()));
    }

    #[test]
    fn test_delete_session() {
        let (storage, _temp) = create_test_backend();
        let options = create_test_signer_options();
        let signer = Signer::open(options, storage);

        let client = "test_client";
        let session = SignerSession {
            client: client.to_string(),
            share: create_test_share(0),
            group: create_test_group(1, 2),
            recovery: true,
            created_at: now(),
            deactivated_at: None,
            last_activity: now(),
            email: Some("test@example.com".to_string()),
            email_hash: Some("hash123".to_string()),
            password_hash: None,
        };

        signer.add_session(client, session);
        assert!(signer.sessions.get(client).is_some());

        signer.delete_session(client);
        assert!(signer.sessions.get(client).is_none());
    }

    #[test]
    fn test_rate_limiting() {
        let (storage, _temp) = create_test_backend();
        let options = create_test_signer_options();
        let signer = Signer::open(options, storage);

        let client = "rate_limited_client";

        // First 100 attempts should succeed
        for _ in 0..100 {
            assert!(signer.check_and_record_rate_limit(client));
        }

        // 101st attempt should fail (rate limited)
        assert!(!signer.check_and_record_rate_limit(client));
    }

    #[test]
    fn test_cleanup() {
        let (storage, _temp) = create_test_backend();
        let options = create_test_signer_options();
        let signer = Signer::open(options, storage);

        // Add an old session (more than 30 days ago)
        let old_client = "old_client";
        let old_session = SignerSession {
            client: old_client.to_string(),
            share: create_test_share(0),
            group: create_test_group(1, 2),
            recovery: true,
            created_at: now().saturating_sub(MONTH_SECS + 1),
            deactivated_at: None,
            last_activity: now().saturating_sub(MONTH_SECS + 1),
            email: None,
            email_hash: None,
            password_hash: None,
        };
        signer.add_session(old_client, old_session);

        // Add a recent session
        let recent_client = "recent_client";
        let recent_session = SignerSession {
            client: recent_client.to_string(),
            share: create_test_share(0),
            group: create_test_group(1, 2),
            recovery: true,
            created_at: now(),
            deactivated_at: None,
            last_activity: now(),
            email: None,
            email_hash: None,
            password_hash: None,
        };
        signer.add_session(recent_client, recent_session);

        // Run cleanup
        signer.cleanup();

        // Old session should be deleted
        assert!(signer.sessions.get(old_client).is_none());
        // Recent session should still exist
        assert!(signer.sessions.get(recent_client).is_some());
    }

    #[test]
    fn test_challenge_email_format() {
        let otp = "12345678";
        let email = challenge_email(otp);

        assert!(email.subject.contains("One-Time Password"));
        assert!(email.text.contains(otp));
        assert!(email.html.contains(otp));
        assert!(email.text.contains("15 minutes"));
        assert!(email.html.contains("15 minutes"));
        assert_eq!(email.to, ""); // Should be filled by caller
    }

    #[test]
    fn test_make_session_item() {
        let session = SignerSession {
            client: "client123".to_string(),
            share: create_test_share(1),
            group: create_test_group(2, 3),
            recovery: true,
            created_at: 1234567890,
            deactivated_at: None,
            last_activity: 1234567891,
            email: Some("user@example.com".to_string()),
            email_hash: None,
            password_hash: None,
        };

        let item = make_session_item(&session);

        assert_eq!(item.client.0, "client123");
        assert_eq!(item.idx, 1);
        assert_eq!(item.threshold, 2);
        assert_eq!(item.total, 3);
        assert_eq!(item.created_at, 1234567890);
        assert_eq!(item.email, Some("user@example.com".to_string()));
    }

    fn insert_test_commit(signer: &Signer, commit_id: &str, client: &str, created_at: u64) {
        signer
            .commits_by_client
            .lock()
            .unwrap()
            .entry(client.to_string())
            .or_default()
            .push(CommitEntry {
                commit_id: commit_id.to_string(),
                members: vec![1, 2],
                secret: SecretNonce {
                    idx: 1,
                    hidden_sn: [1u8; 32],
                    binder_sn: [2u8; 32],
                },
                created_at,
            });
    }

    #[test]
    fn test_take_commit_single_use() {
        let (storage, _temp) = create_test_backend();
        let signer = Signer::open(create_test_signer_options(), storage);

        insert_test_commit(&signer, "cid", "client_a", now());

        // First take succeeds; the entry is consumed.
        assert!(signer.take_commit("cid", "client_a").is_some());
        // Replay finds nothing - the nonce is destroyed, never re-signed.
        assert!(signer.take_commit("cid", "client_a").is_none());
    }

    #[test]
    fn test_take_commit_wrong_client() {
        let (storage, _temp) = create_test_backend();
        let signer = Signer::open(create_test_signer_options(), storage);

        insert_test_commit(&signer, "cid", "client_a", now());

        // A different client must not be able to consume the commitment.
        assert!(signer.take_commit("cid", "client_b").is_none());
        // The rightful owner can still consume it afterwards.
        assert!(signer.take_commit("cid", "client_a").is_some());
    }

    #[test]
    fn test_take_commit_unknown_id() {
        let (storage, _temp) = create_test_backend();
        let signer = Signer::open(create_test_signer_options(), storage);
        assert!(signer.take_commit("missing", "client_a").is_none());
    }

    #[test]
    fn test_commit_gc_reaps_expired() {
        let (storage, _temp) = create_test_backend();
        let signer = Signer::open(create_test_signer_options(), storage);

        insert_test_commit(
            &signer,
            "old",
            "client_a",
            now().saturating_sub(COMMIT_TTL_SECS + 1),
        );
        insert_test_commit(&signer, "fresh", "client_a", now());

        signer.cleanup();

        assert!(signer.take_commit("old", "client_a").is_none());
        assert!(signer.take_commit("fresh", "client_a").is_some());
    }

    /// End-to-end two-round flow: register two signers from a dealer-generated
    /// 2-of-2 group, run /sign/commit then /sign/complete for both, and verify
    /// the aggregated nostr event signature. Also asserts single-use enforcement.
    #[test]
    fn test_two_round_sign_and_verify() {
        use crate::nostr::NostrAuth;
        use crate::schema::{SighashVec, SignCompleteRequestInner};
        use frost_taproot::frost::dealer::generate_dealer_package;
        use frost_taproot::sign::combine_partial_sigs;
        use frost_taproot::types::ShareSignature;
        use nostr::secp256k1::schnorr::Signature as SchnorrSig;
        use nostr::util::JsonUtil;
        use nostr::{EventBuilder, Kind, PublicKey};

        fn auth_for(pubkey: &str) -> NostrAuth {
            let now = now();
            let event_json = format!(
                r#"{{"id":"{id}","pubkey":"{pubkey}","created_at":{now},"kind":27235,"tags":[["u","http://localhost:3000/test"],["method","POST"]],"content":"","sig":"{sig}"}}"#,
                id = "a".repeat(64),
                sig = "b".repeat(128),
            );
            NostrAuth {
                pubkey: pubkey.to_string(),
                event: nostr::Event::from_json(event_json).expect("valid test event json"),
            }
        }

        let (storage, _temp) = create_test_backend();
        let signer = Signer::open(create_test_signer_options(), storage);

        // ── Generate a 2-of-2 FROST group ──
        let secrets = [[0x11u8; 32], [0x22u8; 32]];
        let pkg = generate_dealer_package(2, 2, &secrets).unwrap();
        let group = &pkg.group;
        let group_pk_xonly = PublicKey::from_slice(&group.group_pk[1..]).unwrap();

        let low_shares: Vec<_> = pkg.shares[..2]
            .iter()
            .map(|s| SecretShare {
                idx: s.idx,
                seckey: s.seckey,
            })
            .collect();
        let commit_pkgs: Vec<_> = low_shares
            .iter()
            .map(|s| create_commit_pkg(s, None, None))
            .collect();

        let schema_group = Group {
            group_pk: Hex33(hex::encode(group.group_pk)),
            threshold: group.threshold as u32,
            commits: BoundedVec(
                commit_pkgs
                    .iter()
                    .zip(&low_shares)
                    .map(|(c, s)| Commit {
                        idx: c.idx,
                        pubkey: Hex33(hex::encode(get_pubkey_compressed(&s.seckey))),
                        hidden_pn: Hex33(hex::encode(c.hidden_pn)),
                        binder_pn: Hex33(hex::encode(c.binder_pn)),
                    })
                    .collect(),
            ),
        };

        // ── Register one session per signer (clients keyed arbitrarily) ──
        let clients = ["c".repeat(64), "d".repeat(64)];
        for (i, share) in low_shares.iter().enumerate() {
            signer.add_session(
                &clients[i],
                SignerSession {
                    client: clients[i].clone(),
                    share: Share {
                        idx: share.idx,
                        seckey: Hex32(hex::encode(share.seckey)),
                    },
                    group: schema_group.clone(),
                    recovery: false,
                    created_at: now(),
                    deactivated_at: None,
                    last_activity: now(),
                    email: None,
                    email_hash: None,
                    password_hash: None,
                },
            );
        }

        // ── Build an unsigned nostr event ──
        let mut unsigned =
            EventBuilder::new(Kind::TextNote, "two-round hello").build(group_pk_xonly);
        let sighash_hex = hex::encode(unsigned.id().as_bytes());
        let members = vec![1u32, 2u32];

        // ── Round 1: collect fresh public nonces from both signers ──
        let mut commit_results = Vec::new();
        for client in &clients {
            let resp = signer.handle_sign_commit(
                &auth_for(client),
                SignCommitRequest {
                    members: BoundedVec(members.clone()),
                },
            );
            assert!(resp.ok, "commit should succeed");
            commit_results.push(resp.result.unwrap());
        }

        let pnonces: Vec<crate::schema::PublicNonceItem> = commit_results
            .iter()
            .map(|r| crate::schema::PublicNonceItem {
                idx: r.idx,
                hidden_pn: Hex33(r.hidden_pn.0.clone()),
                binder_pn: Hex33(r.binder_pn.0.clone()),
            })
            .collect();

        // ── Build the session request bound to the fresh pnonces ──
        // The complete request carries a single `hash` vector. sid is computed
        // over [hash], byte-identical to the one-message session the client
        // computes.
        let gid = hex::encode(crate::session::test_group_id(&schema_group));
        let template = SignCompleteRequestInner {
            gid: Hex32(gid.clone()),
            sid: Hex32("00".repeat(32)),
            members: BoundedVec(members.clone()),
            hash: SighashVec(vec![Hex32(sighash_hex)]),
            content: None,
            kind: "message".to_string(),
            stamp: 1234567890,
        };
        let sid = hex::encode(crate::session::test_session_id(&schema_group, &template));
        let complete_request = SignCompleteRequestInner {
            sid: Hex32(sid),
            ..template
        };

        // ── Round 2: complete with both signers ──
        let mut psig_results = Vec::new();
        for (i, client) in clients.iter().enumerate() {
            let resp = signer.handle_sign_complete(
                &auth_for(client),
                SignCompleteRequest {
                    commit_id: Hex32(commit_results[i].commit_id.0.clone()),
                    request: complete_request.clone(),
                    pnonces: BoundedVec(pnonces.clone()),
                },
            );
            assert!(resp.ok, "complete should succeed: {}", resp.message);
            psig_results.push(resp.result.unwrap());
        }

        // ── A replayed completion for a consumed commit_id must be refused ──
        let replay = signer.handle_sign_complete(
            &auth_for(&clients[0]),
            SignCompleteRequest {
                commit_id: Hex32(commit_results[0].commit_id.0.clone()),
                request: complete_request.clone(),
                pnonces: BoundedVec(pnonces.clone()),
            },
        );
        assert!(!replay.ok);
        assert_eq!(replay.message, "Commitment not found or already used");

        // ── Aggregate and verify against the real group key ──
        let base: Vec<_> = pnonces.clone();
        let ctxs = crate::session::test_build_contexts(&schema_group, &complete_request, &base);
        let share_sigs: Vec<ShareSignature> = psig_results
            .iter()
            .map(|r| ShareSignature {
                idx: r.idx,
                pubkey: <[u8; 33]>::try_from(hex::decode(&r.pubkey.0).unwrap()).unwrap(),
                psig: <[u8; 32]>::try_from(hex::decode(&r.psig.1.0).unwrap()).unwrap(),
            })
            .collect();
        let final_sig = combine_partial_sigs(&ctxs[0], &share_sigs).unwrap();

        let schnorr_sig = SchnorrSig::from_slice(&final_sig).unwrap();
        let event = unsigned.add_signature(schnorr_sig).unwrap();
        event
            .verify()
            .expect("two-round FROST-signed nostr event must verify");
    }
}
