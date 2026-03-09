package mailer

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
)

type SmtpMailer struct {
	Host     string
	Port     int
	User     string
	Password string
}

func (m SmtpMailer) Send(_ context.Context, fromEmail string, fromName string, email Email) error {
	addr := fmt.Sprintf("%s:%d", m.Host, m.Port)

	var auth smtp.Auth
	if m.User != "" {
		auth = smtp.PlainAuth("", m.User, m.Password, m.Host)
	}

	from := fmt.Sprintf("%s <%s>", fromName, fromEmail)
	msg := strings.Join([]string{
		"From: " + from,
		"To: " + email.To,
		"Subject: " + email.Subject,
		"MIME-Version: 1.0",
		`Content-Type: multipart/alternative; boundary="pomade-boundary"`,
		"",
		"--pomade-boundary",
		"Content-Type: text/plain; charset=UTF-8",
		"",
		email.Text,
		"",
		"--pomade-boundary",
		"Content-Type: text/html; charset=UTF-8",
		"",
		email.HTML,
		"",
		"--pomade-boundary--",
	}, "\r\n")

	return smtp.SendMail(addr, auth, fromEmail, []string{email.To}, []byte(msg))
}
