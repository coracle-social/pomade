package main

type Commit struct {
	Idx      uint32 `json:"idx"`
	Pubkey   string `json:"pubkey"`
	HiddenPn string `json:"hidden_pn"`
	BinderPn string `json:"binder_pn"`
}

type Group struct {
	Commits   []Commit `json:"commits"`
	GroupPk   string   `json:"group_pk"`
	Threshold uint32   `json:"threshold"`
}

type Share struct {
	Idx      uint32 `json:"idx"`
	BinderSn string `json:"binder_sn"`
	HiddenSn string `json:"hidden_sn"`
	Seckey   string `json:"seckey"`
}

type SessionItem struct {
	Pubkey       string  `json:"pubkey"`
	Client       string  `json:"client"`
	CreatedAt    uint64  `json:"created_at"`
	Deactivated  *uint64 `json:"deactivated_at,omitempty"`
	LastActivity uint64  `json:"last_activity"`
	Threshold    uint32  `json:"threshold"`
	Total        uint32  `json:"total"`
	Idx          uint32  `json:"idx"`
	Email        *string `json:"email,omitempty"`
}

type AuthPayload struct {
	EmailHash    string `json:"email_hash"`
	PasswordHash string `json:"password_hash,omitempty"`
	OTP          string `json:"otp,omitempty"`
}

func (a AuthPayload) IsPassword() bool {
	return a.PasswordHash != ""
}

func (a AuthPayload) IsOTP() bool {
	return a.OTP != ""
}

type RegisterRequest struct {
	Share    Share `json:"share"`
	Group    Group `json:"group"`
	Recovery bool  `json:"recovery"`
}

type RegisterResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type SignRequestInner struct {
	Content *string    `json:"content"`
	Hashes  [][]string `json:"hashes"`
	Members []uint32   `json:"members"`
	Stamp   uint64     `json:"stamp"`
	Type    string     `json:"type"`
	Gid     string     `json:"gid"`
	Sid     string     `json:"sid"`
}

type SignRequest struct {
	Request SignRequestInner `json:"request"`
}

type SignResult struct {
	Idx    uint32      `json:"idx"`
	Psigs  [][2]string `json:"psigs"`
	Pubkey string      `json:"pubkey"`
	Sid    string      `json:"sid"`
}

type SignResponse struct {
	OK      bool        `json:"ok"`
	Message string      `json:"message"`
	Result  *SignResult `json:"result,omitempty"`
}

type SignCommitRequest struct {
	Members []uint32 `json:"members"`
}

type SignCommitResult struct {
	CommitID string `json:"commit_id"`
	Idx      uint32 `json:"idx"`
	Pubkey   string `json:"pubkey"`
	HiddenPn string `json:"hidden_pn"`
	BinderPn string `json:"binder_pn"`
}

type SignCommitResponse struct {
	OK      bool              `json:"ok"`
	Message string            `json:"message"`
	Result  *SignCommitResult `json:"result,omitempty"`
}

type PublicNonceItem struct {
	Idx      uint32 `json:"idx"`
	HiddenPn string `json:"hidden_pn"`
	BinderPn string `json:"binder_pn"`
}

type SignCompleteRequestInner struct {
	Content *string  `json:"content"`
	Hash    []string `json:"hash"`
	Members []uint32 `json:"members"`
	Stamp   uint64   `json:"stamp"`
	Type    string   `json:"type"`
	Gid     string   `json:"gid"`
	Sid     string   `json:"sid"`
}

type SignCompleteRequest struct {
	CommitID string                   `json:"commit_id"`
	Request  SignCompleteRequestInner `json:"request"`
	Pnonces  []PublicNonceItem        `json:"pnonces"`
}

type SignCompleteResult struct {
	Idx    uint32    `json:"idx"`
	Psig   [2]string `json:"psig"`
	Pubkey string    `json:"pubkey"`
	Sid    string    `json:"sid"`
}

type SignCompleteResponse struct {
	OK      bool                `json:"ok"`
	Message string              `json:"message"`
	Result  *SignCompleteResult `json:"result,omitempty"`
}

type EcdhRequest struct {
	Idx     uint32   `json:"idx"`
	Members []uint32 `json:"members"`
	EcdhPk  string   `json:"ecdh_pk"`
}

type EcdhResult struct {
	Idx      uint32   `json:"idx"`
	Keyshare string   `json:"keyshare"`
	Members  []uint32 `json:"members"`
	EcdhPk   string   `json:"ecdh_pk"`
}

type EcdhResponse struct {
	OK      bool        `json:"ok"`
	Message string      `json:"message"`
	Result  *EcdhResult `json:"result,omitempty"`
}

type RecoverySetupRequest struct {
	Email        string `json:"email"`
	PasswordHash string `json:"password_hash"`
}

type RecoverySetupResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type ChallengeRequest struct {
	Prefix    string `json:"prefix"`
	EmailHash string `json:"email_hash"`
}

type ChallengeResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type LoginStartRequest struct {
	Auth AuthPayload `json:"auth"`
}

type LoginStartResponse struct {
	OK      bool          `json:"ok"`
	Message string        `json:"message"`
	Items   []SessionItem `json:"items,omitempty"`
}

type LoginSelectRequest struct {
	Client string `json:"client"`
}

type LoginSelectResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Group   *Group `json:"group,omitempty"`
}

type RecoveryStartRequest struct {
	Auth AuthPayload `json:"auth"`
}

type RecoveryStartResponse struct {
	OK      bool          `json:"ok"`
	Message string        `json:"message"`
	Items   []SessionItem `json:"items,omitempty"`
}

type RecoverySelectRequest struct {
	Client string `json:"client"`
}

type RecoverySelectResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Share   *Share `json:"share,omitempty"`
	Group   *Group `json:"group,omitempty"`
}

type SessionListResponse struct {
	OK      bool          `json:"ok"`
	Message string        `json:"message"`
	Items   []SessionItem `json:"items"`
}

type SessionListRequest struct{}

type SessionDeactivateRequest struct {
	Client string `json:"client"`
}

type SessionDeactivateResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type SessionDeleteRequest struct {
	Client string `json:"client"`
}

type SessionDeleteResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}
