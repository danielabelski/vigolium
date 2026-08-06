package smtp_header_injection

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "smtp-header-injection"
	ModuleName  = "SMTP Header Injection"
	ModuleShort = "Detects CRLF injection into email headers (BCC grafting) via out-of-band mail delivery"
)

var (
	ModuleDesc = `**What it means:** An email-bearing parameter is placed into a mail header without stripping CR/LF, so injected input can add mail headers. The scanner grafts a Bcc header at a unique collaborator address the mailer resolves on delivery, producing an out-of-band interaction.

**How it's exploited:** An attacker injects CRLF into an email field to add headers (Bcc, Cc, a forged From), turning a contact form into a relay for spam and phishing.

**Fix:** Strip CR and LF from any value used in a mail header, and build messages with a library that enforces header/body separation.`

	ModuleConfirmation = "Confirmed when a Bcc header grafted onto an email field via CRLF injection causes the application's mailer to resolve/contact a unique collaborator address out of band"
	ModuleSeverity     = severity.Medium
	ModuleConfidence   = severity.Firm
	ModuleTags         = []string{"injection", "smtp", "crlf", "email", "heavy"}
)
