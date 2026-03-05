package mailer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type PostmarkMailer struct {
	Client   *http.Client
	APIToken string
}

func (m PostmarkMailer) Send(ctx context.Context, fromEmail string, fromName string, email Email) error {
	body, _ := json.Marshal(map[string]any{
		"From":     fmt.Sprintf("%s <%s>", fromName, fromEmail),
		"To":       email.To,
		"Subject":  email.Subject,
		"TextBody": email.Text,
		"HtmlBody": email.HTML,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.postmarkapp.com/email", bytes.NewReader(body))
	req.Header.Set("X-Postmark-Server-Token", m.APIToken)
	req.Header.Set("Content-Type", "application/json")
	res, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("postmark error: %s", res.Status)
	}
	return nil
}
