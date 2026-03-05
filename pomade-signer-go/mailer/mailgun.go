package mailer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

type MailgunMailer struct {
	Client *http.Client
	APIKey string
	Domain string
	Region string
}

func (m MailgunMailer) Send(ctx context.Context, fromEmail string, fromName string, email Email) error {
	form := url.Values{}
	form.Set("from", fmt.Sprintf("%s <%s>", fromName, fromEmail))
	form.Set("to", email.To)
	form.Set("subject", email.Subject)
	form.Set("text", email.Text)
	form.Set("html", email.HTML)
	api := "https://api.mailgun.net"
	if strings.ToLower(m.Region) == "eu" {
		api = "https://api.eu.mailgun.net"
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, api+"/v3/"+m.Domain+"/messages", strings.NewReader(form.Encode()))
	req.SetBasicAuth("api", m.APIKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return fmt.Errorf("mailgun error: %s", res.Status)
	}
	return nil
}
