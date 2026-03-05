package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

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
	url := requireEnv("SIGNER_URL")
	secret := requireEnv("POMADE_SECRET")
	listen := os.Getenv("LISTEN_ADDR")
	if listen == "" {
		listen = "0.0.0.0:3000"
	}
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "./signer.db"
	}
	testMode := os.Getenv("TEST_MODE") != ""

	registerPow := uint32(20)
	if testMode {
		registerPow = 0
	}
	if v := os.Getenv("REGISTER_POW"); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil && parsed >= 0 {
			registerPow = uint32(parsed)
		}
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
		scheme := "http"
		if r.TLS != nil {
			scheme = "https"
		}
		if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
			scheme = strings.TrimSpace(strings.Split(forwarded, ",")[0])
		}
		host := r.Host
		if forwardedHost := r.Header.Get("X-Forwarded-Host"); forwardedHost != "" {
			host = strings.TrimSpace(strings.Split(forwardedHost, ",")[0])
		}
		expectedURL := scheme + "://" + host + r.URL.Path
		res := signer.Handle(r.URL.Path, r.Method, r.Header.Get("Authorization"), expectedURL, body)
		_ = json.NewEncoder(w).Encode(res)
	})

	log.Printf("listening on %s", listen)
	if err := http.ListenAndServe(listen, h); err != nil {
		log.Fatal(err)
	}
}
