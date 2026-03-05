package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"

	"fiatjaf.com/nostr"
)

type NostrAuth struct {
	Pubkey nostr.PubKey
	Event  nostr.Event
}

func parseAuth(header string, method string, expectedURL string) *NostrAuth {
	token := strings.TrimSpace(header)
	parts := strings.SplitN(token, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "nostr" {
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var event nostr.Event
	if err := json.Unmarshal(decoded, &event); err != nil {
		return nil
	}
	if event.Kind != nostr.KindHTTPAuth {
		return nil
	}
	if !event.CheckID() {
		return nil
	}
	if !event.VerifySignature() {
		return nil
	}
	if event.CreatedAt < nostr.Now()-60 || event.CreatedAt > nostr.Now()+60 {
		return nil
	}
	normalizedExpected, err := nostr.NormalizeHTTPURL(expectedURL)
	if err != nil {
		return nil
	}
	hasURL := false
	hasMethod := false
	for _, tag := range event.Tags {
		if len(tag) < 2 {
			continue
		}
		switch tag[0] {
		case "u":
			normalizedTagURL, err := nostr.NormalizeHTTPURL(tag[1])
			if err == nil && normalizedTagURL == normalizedExpected {
				hasURL = true
			}
		case "method":
			if strings.EqualFold(tag[1], method) {
				hasMethod = true
			}
		}
	}
	if !hasURL || !hasMethod {
		return nil
	}
	return &NostrAuth{Pubkey: event.PubKey, Event: event}
}
