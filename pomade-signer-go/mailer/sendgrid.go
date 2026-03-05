package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type SendgridMailer struct {
	Client *http.Client
	APIKey string
}

func (m SendgridMailer) Send(ctx context.Context, fromEmail string, fromName string, email Email) error {
	body, _ := json.Marshal(map[string]any{
		"personalizations": []any{map[string]any{"to": []any{map[string]any{"email": email.To}}}},
		"from":             map[string]any{"email": fromEmail, "name": fromName},
		"subject":          email.Subject,
		"content": []any{
			map[string]any{"type": "text/plain", "value": email.Text},
			map[string]any{"type": "text/html", "value": email.HTML},
		},
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.sendgrid.com/v3/mail/send", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+m.APIKey)
	req.Header.Set("Content-Type", "application/json")
	res, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("sendgrid error: %s", res.Status)
	}
	return nil
}
