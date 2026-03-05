package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/coracle-social/pomade/pomade-signer-go/mailer"
)

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("%s must be set", key)
	}
	return v
}

func buildMailer(provider string, client *http.Client) mailer.Mailer {
	switch provider {
	case "postmark":
		return mailer.PostmarkMailer{Client: client, APIToken: requireEnv("POSTMARK_API_TOKEN")}
	case "sendgrid":
		return mailer.SendgridMailer{Client: client, APIKey: requireEnv("SENDGRID_API_KEY")}
	case "mailgun":
		return mailer.MailgunMailer{
			Client: client,
			APIKey: requireEnv("MAILGUN_API_KEY"),
			Domain: requireEnv("MAILGUN_DOMAIN"),
			Region: os.Getenv("MAILGUN_API_REGION"),
		}
	case "sendlayer":
		return mailer.SendlayerMailer{Client: client, APIKey: requireEnv("SENDLAYER_API_KEY")}
	case "resend":
		return mailer.ResendMailer{Client: client, APIKey: requireEnv("RESEND_API_KEY")}
	default:
		log.Fatalf("unknown MAIL_PROVIDER: %s", provider)
		return nil
	}
}

func main() {
	url := requireEnv("POMADE_URL")
	port := os.Getenv("POMADE_PORT")
	if port == "" {
		port = "3000"
	}
	secret := requireEnv("POMADE_SECRET")
	listen := fmt.Sprintf("0.0.0.0:%s", port)
	dbPath := os.Getenv("POMADE_DATABASE")
	if dbPath == "" {
		dbPath = "./signer.db"
	}
	testMode := os.Getenv("TEST_MODE") != ""

	registerPow := uint32(20)
	if testMode {
		registerPow = 0
	}

	argonM := uint32(64 * 1024)
	if testMode {
		argonM = 1024
	}

	fromEmail := os.Getenv("MAIL_FROM_EMAIL")
	if fromEmail == "" {
		fromEmail = "noreply@example.com"
	}
	fromName := os.Getenv("MAIL_FROM_NAME")
	if fromName == "" {
		fromName = "Pomade Signer"
	}

	httpClient := &http.Client{}
	provider := os.Getenv("MAIL_PROVIDER")
	if !testMode && provider == "" {
		log.Fatal("MAIL_PROVIDER must be set when TEST_MODE is not enabled")
	}

	var m mailer.Mailer
	if provider != "" {
		m = buildMailer(provider, httpClient)
	}

	backend, err := OpenBboltEncrypted(dbPath, secret)
	if err != nil {
		log.Fatalf("failed to open db: %v", err)
	}
	defer backend.Close()

	signer := OpenSigner(SignerOptions{
		URL:         url,
		RegisterPow: registerPow,
		ArgonM:      argonM,
		FromEmail:   fromEmail,
		FromName:    fromName,
		Mailer:      m,
		TestMode:    testMode,
	}, backend)

	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")
		w.Header().Set("Content-Type", "application/json")

		var body json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "message": "Failed to validate request data."})
			return
		}
		res := signer.Handle(r.URL.Path, r.Method, r.Header.Get("Authorization"), url+r.URL.Path, body)
		_ = json.NewEncoder(w).Encode(res)
	})

	log.Printf("listening on %s", listen)
	if err := http.ListenAndServe(listen, h); err != nil {
		log.Fatal(err)
	}
}
