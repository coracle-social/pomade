package mailer

import "context"

type Email struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

type Mailer interface {
	Send(ctx context.Context, fromEmail string, fromName string, email Email) error
}
