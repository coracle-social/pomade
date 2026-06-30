package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coracle-social/pomade/pomade-signer-go/mailer"
	"github.com/frost-taproot/frost-taproot-go/commit"
	"github.com/frost-taproot/frost-taproot-go/helpers"
	"github.com/frost-taproot/frost-taproot-go/types"
	"golang.org/x/crypto/argon2"
)

//go:embed challenge.html
var challengeHTML string

const monthSecs uint64 = 30 * 24 * 3600
const minuteSecs uint64 = 60

var clientRateLimits = RateLimitConfig{MaxAttempts: 500, WindowSeconds: 60}
var emailRateLimits = RateLimitConfig{MaxAttempts: 5, WindowSeconds: 120}

const commitTTLSecs uint64 = 2 * 60
const maxMembers = 5

type SignerOptions struct {
	URL         string
	RegisterPow uint32
	ArgonM      uint32
	FromEmail   string
	FromName    string
	Mailer      mailer.Mailer
	TestMode    bool
}

type SignerSession struct {
	Client       string  `json:"client"`
	Share        Share   `json:"share"`
	Group        Group   `json:"group"`
	Recovery     bool    `json:"recovery"`
	CreatedAt    uint64  `json:"created_at"`
	Deactivated  *uint64 `json:"deactivated_at"`
	LastActivity uint64  `json:"last_activity"`
	Email        *string `json:"email"`
	EmailHash    *string `json:"email_hash"`
	PasswordHash *string `json:"password_hash"`
}

type SessionIndex struct {
	Clients []string `json:"clients"`
}

type SignerRecovery struct {
	CreatedAt uint64   `json:"created_at"`
	Clients   []string `json:"clients"`
}

type SignerLogin struct {
	CreatedAt uint64   `json:"created_at"`
	Clients   []string `json:"clients"`
}

type SignerChallenge struct {
	CreatedAt uint64 `json:"created_at"`
	OTP       string `json:"otp"`
}

// commitEntry holds the in-memory, non-durable state for a single round-1
// commitment. The secret nonce is server-only and never serialized or returned.
type commitEntry struct {
	commitID  string
	members   []uint32
	secret    types.SecretNonce
	createdAt uint64
}

type Signer struct {
	options SignerOptions

	logins               Collection[SignerLogin]
	sessions             Collection[SignerSession]
	recoveries           Collection[SignerRecovery]
	challenges           Collection[SignerChallenge]
	sessionsByEmailHash  Collection[SessionIndex]
	rateLimitByEmailHash Collection[RateLimitBucket]
	rateLimitByClient    Collection[RateLimitBucket]

	commitMu        sync.Mutex
	commitsByClient map[string][]*commitEntry
}

const generatorX = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

func OpenSigner(options SignerOptions, backend StorageBackend) *Signer {
	storage := NewStorage(backend)
	return &Signer{
		options:              options,
		logins:               GetCollection[SignerLogin](storage, "logins"),
		sessions:             GetCollection[SignerSession](storage, "sessions"),
		recoveries:           GetCollection[SignerRecovery](storage, "recoveries"),
		challenges:           GetCollection[SignerChallenge](storage, "challenges"),
		sessionsByEmailHash:  GetCollection[SessionIndex](storage, "sessionsByEmailHash"),
		rateLimitByEmailHash: GetCollection[RateLimitBucket](storage, "rateLimitByEmailHash"),
		rateLimitByClient:    GetCollection[RateLimitBucket](storage, "rateLimitByClient"),
		commitsByClient:      make(map[string][]*commitEntry),
	}
}

func randomInt(min uint32, max uint32) uint32 {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	v := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	if max <= min {
		return min
	}
	return min + (v % (max - min))
}

func makeSessionItem(session SignerSession) SessionItem {
	pubkey := ""
	if len(session.Group.GroupPk) >= 66 {
		pubkey = session.Group.GroupPk[2:]
	}
	return SessionItem{
		Pubkey:       pubkey,
		Client:       session.Client,
		CreatedAt:    session.CreatedAt,
		Deactivated:  session.Deactivated,
		LastActivity: session.LastActivity,
		Threshold:    session.Group.Threshold,
		Total:        uint32(len(session.Group.Commits)),
		Idx:          session.Share.Idx,
		Email:        session.Email,
	}
}

func (s *Signer) cleanup() {
	cutoff15m := nowSec() - 15*minuteSecs
	cutoffMonth := nowSec() - monthSecs

	for k, r := range s.recoveries.Entries() {
		if r.CreatedAt < cutoff15m {
			s.recoveries.Delete(k)
		}
	}
	for k, l := range s.logins.Entries() {
		if l.CreatedAt < cutoff15m {
			s.logins.Delete(k)
		}
	}
	for k, c := range s.challenges.Entries() {
		if c.CreatedAt < cutoff15m {
			s.challenges.Delete(k)
		}
	}
	for k, b := range s.rateLimitByEmailHash.Entries() {
		if b.LastAttempt < nowSec()-emailRateLimits.WindowSeconds {
			s.rateLimitByEmailHash.Delete(k)
		}
	}
	for k, b := range s.rateLimitByClient.Entries() {
		if b.LastAttempt < nowSec()-clientRateLimits.WindowSeconds {
			s.rateLimitByClient.Delete(k)
		}
	}
	for k, sess := range s.sessions.Entries() {
		if sess.LastActivity < cutoffMonth {
			s.deleteSession(k)
		}
	}

	commitCutoff := nowSec() - commitTTLSecs
	s.commitMu.Lock()
	for client, entries := range s.commitsByClient {
		kept := entries[:0]
		for _, entry := range entries {
			if entry.createdAt >= commitCutoff {
				kept = append(kept, entry)
			}
		}
		if len(kept) == 0 {
			delete(s.commitsByClient, client)
		} else {
			s.commitsByClient[client] = kept
		}
	}
	s.commitMu.Unlock()
}

func (s *Signer) checkAndRecordRateLimit(client string) bool {
	b := s.rateLimitByClient.Get(client)
	if isRateLimited(b, clientRateLimits) {
		return false
	}
	s.rateLimitByClient.Set(client, recordAttempt(b, clientRateLimits))
	return true
}

func (s *Signer) checkKeyReuse(client string) bool {
	if s.sessions.Get(client) != nil {
		return true
	}
	if s.recoveries.Get(client) != nil {
		return true
	}
	if s.logins.Get(client) != nil {
		return true
	}
	return false
}

func (s *Signer) addSession(client string, session SignerSession) {
	s.sessions.Set(client, session)
	if session.EmailHash == nil {
		return
	}
	idx := s.sessionsByEmailHash.Get(*session.EmailHash)
	if idx == nil {
		s.sessionsByEmailHash.Set(*session.EmailHash, SessionIndex{Clients: []string{client}})
		return
	}
	for _, c := range idx.Clients {
		if c == client {
			s.sessionsByEmailHash.Set(*session.EmailHash, *idx)
			return
		}
	}
	idx.Clients = append(idx.Clients, client)
	s.sessionsByEmailHash.Set(*session.EmailHash, *idx)
}

func (s *Signer) deactivateSession(client string) {
	session := s.sessions.Get(client)
	if session == nil {
		return
	}
	t := nowSec()
	session.Deactivated = &t
	s.sessions.Set(client, *session)
}

func (s *Signer) deleteSession(client string) {
	session := s.sessions.Get(client)
	if session == nil {
		return
	}
	if session.EmailHash != nil {
		idx := s.sessionsByEmailHash.Get(*session.EmailHash)
		if idx != nil {
			next := make([]string, 0, len(idx.Clients))
			for _, c := range idx.Clients {
				if c != client {
					next = append(next, c)
				}
			}
			if len(next) == 0 {
				s.sessionsByEmailHash.Delete(*session.EmailHash)
			} else {
				s.sessionsByEmailHash.Set(*session.EmailHash, SessionIndex{Clients: next})
			}
		}
	}
	s.sessions.Delete(client)
}

func hashEmail(email string, url string, argonM uint32) string {
	out := argon2.IDKey([]byte(email), []byte(url), 3, argonM, 2, 32)
	return hex.EncodeToString(out)
}

var hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

func isHex64(s string) bool {
	return hex64Re.MatchString(s)
}

func (s *Signer) getAuthenticatedSessions(auth AuthPayload) []SignerSession {
	if !isHex64(auth.EmailHash) {
		return nil
	}
	b := s.rateLimitByEmailHash.Get(auth.EmailHash)
	if isRateLimited(b, emailRateLimits) {
		return nil
	}
	idx := s.sessionsByEmailHash.Get(auth.EmailHash)
	if idx == nil {
		s.rateLimitByEmailHash.Set(auth.EmailHash, recordAttempt(b, emailRateLimits))
		return nil
	}
	items := make([]SignerSession, 0, len(idx.Clients))
	if auth.IsPassword() {
		for _, c := range idx.Clients {
			sess := s.sessions.Get(c)
			if sess == nil || sess.PasswordHash == nil {
				continue
			}
			if subtle.ConstantTimeCompare([]byte(*sess.PasswordHash), []byte(auth.PasswordHash)) == 1 {
				items = append(items, *sess)
			}
		}
	} else if auth.IsOTP() {
		challenge := s.challenges.Get(auth.EmailHash)
		if challenge != nil {
			s.challenges.Delete(auth.EmailHash)
			if subtle.ConstantTimeCompare([]byte(challenge.OTP), []byte(auth.OTP)) == 1 {
				for _, c := range idx.Clients {
					sess := s.sessions.Get(c)
					if sess != nil {
						items = append(items, *sess)
					}
				}
			}
		}
	}
	if len(items) == 0 {
		s.rateLimitByEmailHash.Set(auth.EmailHash, recordAttempt(b, emailRateLimits))
	}
	return items
}

func (s *Signer) handleRegister(auth NostrAuth, data RegisterRequest) RegisterResponse {
	client := auth.Pubkey.Hex()
	if s.checkKeyReuse(client) {
		return RegisterResponse{OK: false, Message: "Do not re-use session keys."}
	}
	// The client key must be distinct from the user's pubkey (PROTOCOL.md).
	if len(data.Group.GroupPk) >= 66 && client == data.Group.GroupPk[2:] {
		return RegisterResponse{OK: false, Message: "Client key must be distinct from the user key."}
	}
	idBytes := auth.Event.ID
	if getPow(idBytes) < s.options.RegisterPow {
		return RegisterResponse{OK: false, Message: "Registration requires 16 bits of proof of work (NIP-13)."}
	}
	threshold := int(data.Group.Threshold)
	total := len(data.Group.Commits)
	if threshold == 0 || threshold > total {
		return RegisterResponse{OK: false, Message: "Invalid group threshold."}
	}
	if !isGroupMember(data.Group, data.Share) {
		return RegisterResponse{OK: false, Message: "Share does not belong to the provided group."}
	}
	seen := map[uint32]bool{}
	for _, c := range data.Group.Commits {
		if seen[c.Idx] {
			return RegisterResponse{OK: false, Message: "Group contains duplicate member indices."}
		}
		seen[c.Idx] = true
	}
	if !seen[data.Share.Idx] {
		return RegisterResponse{OK: false, Message: "Share index not found in group commits."}
	}
	if s.sessions.Get(client) != nil {
		return RegisterResponse{OK: false, Message: "Client is already registered."}
	}
	s.addSession(client, SignerSession{
		Client:       client,
		Share:        data.Share,
		Group:        data.Group,
		Recovery:     data.Recovery,
		CreatedAt:    nowSec(),
		LastActivity: nowSec(),
	})
	return RegisterResponse{OK: true, Message: "Your key has been registered"}
}

func (s *Signer) handleRecoverySetup(auth NostrAuth, data RecoverySetupRequest) RecoverySetupResponse {
	client := auth.Pubkey.Hex()
	session := s.sessions.Get(client)
	if session == nil {
		return RecoverySetupResponse{OK: false, Message: "No session found."}
	}
	if !session.Recovery {
		return RecoverySetupResponse{OK: false, Message: "Recovery is disabled on this session."}
	}
	if session.CreatedAt < nowSec()-15*minuteSecs {
		return RecoverySetupResponse{OK: false, Message: "Recovery method must be set within 15 minutes of session."}
	}
	if session.Email != nil {
		return RecoverySetupResponse{OK: false, Message: "Recovery has already been initialized."}
	}
	if !isHex64(data.PasswordHash) {
		return RecoverySetupResponse{OK: false, Message: "Recovery method password hash must be an argon2id hash of user email and password."}
	}
	emailHash := hashEmail(data.Email, s.options.URL, s.options.ArgonM)
	session.Email = &data.Email
	session.EmailHash = &emailHash
	session.PasswordHash = &data.PasswordHash
	session.LastActivity = nowSec()
	s.addSession(client, *session)
	return RecoverySetupResponse{OK: true, Message: "Recovery method successfully initialized."}
}

func challengeEmail(otp string) mailer.Email {
	return mailer.Email{
		Subject: "Your One-Time Password",
		Text:    fmt.Sprintf("Someone attempted to log in using your email address. If this was you, please continue by copying the one-time password below:\n\n%s\n\nThis code will expire in 15 minutes.\n\nIf you did not request this code, please ignore this email.", otp),
		HTML:    strings.ReplaceAll(challengeHTML, "{{otp}}", otp),
	}
}

var prefixRe = regexp.MustCompile(`^\d{2}$`)

func (s *Signer) handleChallenge(data ChallengeRequest) ChallengeResponse {
	if !prefixRe.MatchString(data.Prefix) || !isHex64(data.EmailHash) {
		return ChallengeResponse{OK: true, Message: "Please check your email inbox for a one-time password."}
	}
	b := s.rateLimitByEmailHash.Get(data.EmailHash)
	if isRateLimited(b, emailRateLimits) {
		return ChallengeResponse{OK: true, Message: "Please check your email inbox for a one-time password."}
	}
	// Always record an attempt to prevent email hash enumeration via rate limit side-channel.
	s.rateLimitByEmailHash.Set(data.EmailHash, recordAttempt(b, emailRateLimits))
	idx := s.sessionsByEmailHash.Get(data.EmailHash)
	if idx != nil && len(idx.Clients) > 0 {
		sess := s.sessions.Get(idx.Clients[0])
		if sess != nil && sess.Email != nil {
			otp := fmt.Sprintf("%s%d", data.Prefix, randomInt(100000, 1000000))
			s.challenges.Set(data.EmailHash, SignerChallenge{CreatedAt: nowSec(), OTP: otp})
			if s.options.TestMode {
				fmt.Printf("[challenge] otp=%s to=%s\n", otp, *sess.Email)
			}
			if !s.options.TestMode && s.options.Mailer != nil {
				mail := challengeEmail(otp)
				mail.To = *sess.Email
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				if err := s.options.Mailer.Send(ctx, s.options.FromEmail, s.options.FromName, mail); err != nil {
					log.Printf("failed to send challenge email: %v", err)
				}
			}
		}
	}
	return ChallengeResponse{OK: true, Message: "Please check your email inbox for a one-time password."}
}

func (s *Signer) handleRecoveryStart(auth NostrAuth, data RecoveryStartRequest) RecoveryStartResponse {
	client := auth.Pubkey.Hex()
	if s.checkKeyReuse(client) {
		return RecoveryStartResponse{OK: false, Message: "Do not re-use session keys."}
	}
	sessions := s.getAuthenticatedSessions(data.Auth)
	if len(sessions) == 0 {
		return RecoveryStartResponse{OK: false, Message: "No sessions found."}
	}
	clients := make([]string, 0, len(sessions))
	items := make([]SessionItem, 0, len(sessions))
	for _, ss := range sessions {
		clients = append(clients, ss.Client)
		items = append(items, makeSessionItem(ss))
	}
	s.recoveries.Set(client, SignerRecovery{CreatedAt: nowSec(), Clients: clients})
	return RecoveryStartResponse{OK: true, Message: "Successfully retrieved recovery options.", Items: items}
}

func (s *Signer) handleRecoverySelect(auth NostrAuth, data RecoverySelectRequest) RecoverySelectResponse {
	client := auth.Pubkey.Hex()
	recovery := s.recoveries.Get(client)
	if recovery == nil {
		return RecoverySelectResponse{OK: false, Message: "No active recovery found."}
	}
	s.recoveries.Delete(client)
	ok := false
	for _, c := range recovery.Clients {
		if c == data.Client {
			ok = true
			break
		}
	}
	if !ok {
		return RecoverySelectResponse{OK: false, Message: "Invalid session selected for recovery."}
	}
	session := s.sessions.Get(data.Client)
	if session == nil {
		return RecoverySelectResponse{OK: false, Message: "Recovery session not found."}
	}
	return RecoverySelectResponse{OK: true, Message: "Recovery successfully completed.", Group: &session.Group, Share: &session.Share}
}

func (s *Signer) handleLoginStart(auth NostrAuth, data LoginStartRequest) LoginStartResponse {
	client := auth.Pubkey.Hex()
	if s.checkKeyReuse(client) {
		return LoginStartResponse{OK: false, Message: "Do not re-use session keys."}
	}
	sessions := s.getAuthenticatedSessions(data.Auth)
	if len(sessions) == 0 {
		return LoginStartResponse{OK: false, Message: "No sessions found."}
	}
	clients := make([]string, 0, len(sessions))
	items := make([]SessionItem, 0, len(sessions))
	for _, ss := range sessions {
		clients = append(clients, ss.Client)
		items = append(items, makeSessionItem(ss))
	}
	s.logins.Set(client, SignerLogin{CreatedAt: nowSec(), Clients: clients})
	return LoginStartResponse{OK: true, Message: "Successfully retrieved login options.", Items: items}
}

func (s *Signer) handleLoginSelect(auth NostrAuth, data LoginSelectRequest) LoginSelectResponse {
	client := auth.Pubkey.Hex()
	login := s.logins.Get(client)
	if login == nil {
		return LoginSelectResponse{OK: false, Message: "No active login found."}
	}
	s.logins.Delete(client)
	ok := false
	for _, c := range login.Clients {
		if c == data.Client {
			ok = true
			break
		}
	}
	if !ok {
		return LoginSelectResponse{OK: false, Message: "Invalid session selected for login."}
	}
	session := s.sessions.Get(data.Client)
	if session == nil {
		return LoginSelectResponse{OK: false, Message: "Login session not found."}
	}
	group := session.Group
	s.addSession(client, SignerSession{
		Client:       client,
		Share:        session.Share,
		Group:        session.Group,
		Email:        session.Email,
		EmailHash:    session.EmailHash,
		PasswordHash: session.PasswordHash,
		Recovery:     true,
		CreatedAt:    nowSec(),
		LastActivity: nowSec(),
	})
	return LoginSelectResponse{OK: true, Message: "Login successfully completed.", Group: &group}
}

func containsIdx(members []uint32, idx uint32) bool {
	for _, m := range members {
		if m == idx {
			return true
		}
	}
	return false
}

func randomCommitID() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// takeCommit performs an atomic check-and-remove within the requesting client's
// slice. Looking up only within that client's commitments structurally prevents
// access to another client's commitment. At most one caller can ever succeed for
// a given commit id, which guarantees a fresh nonce signs exactly once. The
// returned entry is the only remaining copy; signing happens outside the lock.
func (s *Signer) takeCommit(commitID string, client string) (*commitEntry, bool) {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	entries := s.commitsByClient[client]
	for i, entry := range entries {
		if subtle.ConstantTimeCompare([]byte(entry.commitID), []byte(commitID)) != 1 {
			continue
		}
		next := append(entries[:i], entries[i+1:]...)
		if len(next) == 0 {
			delete(s.commitsByClient, client)
		} else {
			s.commitsByClient[client] = next
		}
		return entry, true
	}
	return nil, false
}

func (s *Signer) putCommit(client string, entry *commitEntry) string {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()
	entry.commitID = randomCommitID()
	s.commitsByClient[client] = append(s.commitsByClient[client], entry)
	return entry.commitID
}

func (s *Signer) handleSignCommit(auth NostrAuth, data SignCommitRequest) SignCommitResponse {
	client := auth.Pubkey.Hex()
	session := s.sessions.Get(client)
	if session == nil {
		return SignCommitResponse{OK: false, Message: "No session found for client"}
	}
	if session.Deactivated != nil {
		return SignCommitResponse{OK: false, Message: "Session is deactivated"}
	}
	if !s.checkAndRecordRateLimit(client) {
		return SignCommitResponse{OK: false, Message: "Rate limit exceeded. Please try again later."}
	}
	if len(data.Members) == 0 || len(data.Members) > maxMembers {
		return SignCommitResponse{OK: false, Message: "Invalid members list"}
	}
	if !containsIdx(data.Members, session.Share.Idx) {
		return SignCommitResponse{OK: false, Message: "Signer index not present in members list"}
	}

	seckey, ok := decodeHex32(session.Share.Seckey)
	if !ok {
		return SignCommitResponse{OK: false, Message: "Failed to create commitment"}
	}
	secretShare := types.SecretShare{ID: session.Share.Idx, Seckey: seckey}
	pkg := commit.CreateCommitPkg(&secretShare, nil, nil)

	members := append([]uint32(nil), data.Members...)
	commitID := s.putCommit(client, &commitEntry{
		members:   members,
		secret:    pkg.SecretNonce(),
		createdAt: nowSec(),
	})

	pubkey := ""
	for _, c := range session.Group.Commits {
		if c.Idx == session.Share.Idx {
			pubkey = c.Pubkey
			break
		}
	}

	session.LastActivity = nowSec()
	s.sessions.Set(client, *session)
	return SignCommitResponse{OK: true, Message: "Commitment created", Result: &SignCommitResult{
		CommitID: commitID,
		Idx:      session.Share.Idx,
		Pubkey:   pubkey,
		HiddenPn: hex.EncodeToString(pkg.HiddenPn[:]),
		BinderPn: hex.EncodeToString(pkg.BinderPn[:]),
	}}
}

func (s *Signer) handleSignComplete(auth NostrAuth, data SignCompleteRequest) SignCompleteResponse {
	client := auth.Pubkey.Hex()
	session := s.sessions.Get(client)
	if session == nil {
		return SignCompleteResponse{OK: false, Message: "No session found for client"}
	}
	if session.Deactivated != nil {
		return SignCompleteResponse{OK: false, Message: "Session is deactivated"}
	}
	if !s.checkAndRecordRateLimit(client) {
		return SignCompleteResponse{OK: false, Message: "Rate limit exceeded. Please try again later."}
	}

	if len(data.Request.Hash) == 0 {
		return SignCompleteResponse{OK: false, Message: "Failed to sign event"}
	}

	// Atomic single-use: the nonce is consumed here and never restored, even if
	// signing below fails. A second completion for this commit id is refused.
	entry, ok := s.takeCommit(data.CommitID, client)
	if !ok {
		return SignCompleteResponse{OK: false, Message: "Commitment not found or already used"}
	}

	if !verifySessionPkg(session.Group, data.Request) {
		return SignCompleteResponse{OK: false, Message: "Failed to sign event"}
	}
	if !containsIdx(data.Request.Members, session.Share.Idx) {
		return SignCompleteResponse{OK: false, Message: "Signer index not present in members list"}
	}
	if !sameMembers(entry.members, data.Request.Members) {
		return SignCompleteResponse{OK: false, Message: "Failed to sign event"}
	}
	if !validatePnonces(session.Group, data.Request.Members, data.Pnonces, entry.secret) {
		return SignCompleteResponse{OK: false, Message: "Failed to sign event"}
	}

	psig, ok := createPsigPkgWithNonce(session.Group, data.Request, session.Share, entry.secret, data.Pnonces)
	if !ok {
		return SignCompleteResponse{OK: false, Message: "Failed to sign event"}
	}
	session.LastActivity = nowSec()
	s.sessions.Set(client, *session)
	return SignCompleteResponse{OK: true, Message: "Successfully signed event", Result: psig}
}

func sameMembers(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// validatePnonces enforces that the supplied public nonce set matches the chosen
// members exactly, every nonce belongs to a group member, and the entry for this
// signer's own idx equals the public nonce derived from the stored secret nonce.
func validatePnonces(group Group, members []uint32, pnonces []PublicNonceItem, secret types.SecretNonce) bool {
	if len(pnonces) != len(members) || len(pnonces) > maxMembers {
		return false
	}
	groupIdx := map[uint32]bool{}
	for _, c := range group.Commits {
		groupIdx[c.Idx] = true
	}
	expectHidden := helpers.GetPubkey(secret.HiddenSn)
	expectBinder := helpers.GetPubkey(secret.BinderSn)
	for _, m := range members {
		var match *PublicNonceItem
		for i := range pnonces {
			if pnonces[i].Idx == m {
				if match != nil {
					return false
				}
				match = &pnonces[i]
			}
		}
		if match == nil || !groupIdx[m] {
			return false
		}
		if m == secret.ID {
			hidden, ok := decodeHex33(match.HiddenPn)
			if !ok || hidden != expectHidden {
				return false
			}
			binder, ok := decodeHex33(match.BinderPn)
			if !ok || binder != expectBinder {
				return false
			}
		}
	}
	return true
}

func (s *Signer) handleEcdh(auth NostrAuth, data EcdhRequest) EcdhResponse {
	client := auth.Pubkey.Hex()
	session := s.sessions.Get(client)
	if session == nil {
		return EcdhResponse{OK: false, Message: "No session found for client"}
	}
	if session.Deactivated != nil {
		return EcdhResponse{OK: false, Message: "Session is deactivated"}
	}
	if !s.checkAndRecordRateLimit(client) {
		return EcdhResponse{OK: false, Message: "Rate limit exceeded. Please try again later."}
	}
	if data.EcdhPk == generatorX {
		return EcdhResponse{OK: false, Message: "Invalid ECDH public key"}
	}
	if !containsIdx(data.Members, session.Share.Idx) {
		return EcdhResponse{OK: false, Message: "Signer index not present in members list"}
	}
	result, ok := createEcdhPkg(data, session.Share)
	if !ok {
		return EcdhResponse{OK: false, Message: "Key derivation failed"}
	}
	session.LastActivity = nowSec()
	s.sessions.Set(client, *session)
	return EcdhResponse{OK: true, Message: "Successfully derived shared secret", Result: result}
}

func (s *Signer) handleSessionList(auth NostrAuth) SessionListResponse {
	pubkey := auth.Pubkey.Hex()
	items := make([]SessionItem, 0)
	for _, sess := range s.sessions.Entries() {
		if len(sess.Group.GroupPk) >= 66 && sess.Group.GroupPk[2:] == pubkey {
			items = append(items, makeSessionItem(sess))
		}
	}
	return SessionListResponse{OK: true, Message: "Successfully retrieved session list.", Items: items}
}

func (s *Signer) handleSessionDeactivate(auth NostrAuth, data SessionDeactivateRequest) SessionDeactivateResponse {
	pubkey := auth.Pubkey.Hex()
	session := s.sessions.Get(data.Client)
	if session != nil && len(session.Group.GroupPk) >= 66 && session.Group.GroupPk[2:] == pubkey {
		s.deactivateSession(data.Client)
		return SessionDeactivateResponse{OK: true, Message: "Successfully deactivated selected session."}
	}
	return SessionDeactivateResponse{OK: false, Message: "Failed to deactivate selected session."}
}

func (s *Signer) handleSessionDelete(auth NostrAuth, data SessionDeleteRequest) SessionDeleteResponse {
	pubkey := auth.Pubkey.Hex()
	session := s.sessions.Get(data.Client)
	if session != nil && len(session.Group.GroupPk) >= 66 && session.Group.GroupPk[2:] == pubkey {
		s.deleteSession(data.Client)
		return SessionDeleteResponse{OK: true, Message: "Successfully deleted selected session."}
	}
	return SessionDeleteResponse{OK: false, Message: "Failed to delete selected session."}
}

func decodeJSON[T any](raw json.RawMessage) (*T, bool) {
	var data T
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, false
	}
	return &data, true
}

func (s *Signer) Handle(path string, method string, authHeader string, expectedURL string, body json.RawMessage) any {
	auth := parseAuth(authHeader, method, expectedURL)
	if auth == nil {
		return map[string]any{"ok": false, "message": "Failed to validate authentication."}
	}
	s.cleanup()

	switch path {
	case "/register":
		data, ok := decodeJSON[RegisterRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleRegister(*auth, *data)
	case "/sign/commit":
		data, ok := decodeJSON[SignCommitRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleSignCommit(*auth, *data)
	case "/sign/complete":
		data, ok := decodeJSON[SignCompleteRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleSignComplete(*auth, *data)
	case "/ecdh":
		data, ok := decodeJSON[EcdhRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleEcdh(*auth, *data)
	case "/recovery/setup":
		data, ok := decodeJSON[RecoverySetupRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleRecoverySetup(*auth, *data)
	case "/challenge":
		data, ok := decodeJSON[ChallengeRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleChallenge(*data)
	case "/recovery/start":
		data, ok := decodeJSON[RecoveryStartRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleRecoveryStart(*auth, *data)
	case "/recovery/select":
		data, ok := decodeJSON[RecoverySelectRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleRecoverySelect(*auth, *data)
	case "/login/start":
		data, ok := decodeJSON[LoginStartRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleLoginStart(*auth, *data)
	case "/login/select":
		data, ok := decodeJSON[LoginSelectRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleLoginSelect(*auth, *data)
	case "/session/list":
		data, ok := decodeJSON[SessionListRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		_ = data
		return s.handleSessionList(*auth)
	case "/session/deactivate":
		data, ok := decodeJSON[SessionDeactivateRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleSessionDeactivate(*auth, *data)
	case "/session/delete":
		data, ok := decodeJSON[SessionDeleteRequest](body)
		if !ok {
			return map[string]any{"ok": false, "message": "Failed to validate request data."}
		}
		return s.handleSessionDelete(*auth, *data)
	default:
		return map[string]any{"ok": false, "message": "Not found"}
	}
}
