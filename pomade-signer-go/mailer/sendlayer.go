package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type SendlayerMailer struct {
	Client *http.Client
	APIKey string
}

func (m SendlayerMailer) Send(ctx context.Context, fromEmail string, fromName string, email Email) error {
	body, _ := json.Marshal(map[string]any{
		"from": map[string]any{
			"email": fromEmail,
			"name":  fromName,
		},
		"to":      []any{map[string]any{"email": email.To}},
		"subject": email.Subject,
		"text":    email.Text,
		"html":    email.HTML,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://console.sendlayer.com/api/v1/email", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("sendlayer error: %s", res.Status)
	}
	return nil
}
