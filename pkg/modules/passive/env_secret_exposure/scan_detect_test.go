package env_secret_exposure

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/modules/modkit"
	"github.com/vigolium/vigolium/pkg/output"
	"github.com/vigolium/vigolium/pkg/types/severity"
)

// makeHTTPCtx builds a request/response pair for the given path, response
// Content-Type, and body.
func makeHTTPCtx(path, contentType, body string) *httpmsg.HttpRequestResponse {
	return makeHTTPStatusCtx(path, contentType, body, 200, "OK")
}

func makeHTTPStatusCtx(path, contentType, body string, status int, reason string) *httpmsg.HttpRequestResponse {
	rawReq := []byte(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: example.com\r\n\r\n", path))
	req := httpmsg.NewHttpRequestWithService(
		httpmsg.NewServiceSecure("example.com", 443, true),
		rawReq,
	)
	rawResp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Type: %s\r\n\r\n%s", status, reason, contentType, body)
	resp := httpmsg.NewHttpResponse([]byte(rawResp))
	return httpmsg.NewHttpRequestResponse(req, resp)
}

func TestNew(t *testing.T) {
	t.Parallel()
	m := New()
	require.NotNil(t, m)
	assert.Equal(t, ModuleID, m.ID())
	assert.Equal(t, ModuleName, m.Name())
}

func TestCanProcess_TextResponse(t *testing.T) {
	t.Parallel()
	m := New()
	ctx := makeHTTPCtx("/app.js", "application/javascript", "console.log('hi')")
	assert.True(t, m.CanProcess(ctx))
}

// TestScanPerRequest_FrameworkSecret drives a NEXT_PUBLIC_* secret embedded in a
// JS bundle, exercising the framework env-var pattern path.
func TestScanPerRequest_FrameworkSecret(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const config = {NEXT_PUBLIC_API_SECRET: "s3cr3tValue12345"};`
	ctx := makeHTTPCtx("/_next/static/chunk.js", "application/javascript", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, ModuleID, results[0].ModuleID)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, output.EvidenceGradeCandidate, results[0].EvidenceGrade)
	assert.Equal(t, severity.Medium, results[0].Info.Severity)
	assert.Contains(t, results[0].Info.Name, "Public Environment Variable")
}

// TestScanPerRequest_DotenvFile drives a raw .env file served directly with a
// secret-bearing line, exercising the dotenv detection path.
func TestScanPerRequest_DotenvFile(t *testing.T) {
	t.Parallel()
	m := New()
	body := "DEBUG=true\nSTRIPE_KEY=sk_live_ab" + "cdef123456" + "7890\nPORT=3000\n"
	ctx := makeHTTPCtx("/.env", "text/plain", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results)
	assert.Equal(t, output.RecordKindCandidate, results[0].RecordKind)
	assert.Equal(t, severity.High, results[0].Info.Severity)
	assert.Equal(t, "Credential-Shaped Value in Served Dotenv File", results[0].Info.Name)
}

func TestScanPerRequest_PublicBrowserIdentifiersAreNotSecrets(t *testing.T) {
	t.Parallel()
	tests := []string{
		`const x = {NEXT_PUBLIC_STRIPE_KEY: "pk_live_ab` + `cdefghijkl` + `mnopqrst"};`,
		`const x = {VITE_GOOGLE_API_KEY: "AIzaSyDUMMY_PUBLIC_BROWSER_KEY_123"};`,
		`const x = {REACT_APP_OAUTH_CREDENTIAL: "123456-abcdef.apps.googleusercontent.com"};`,
	}
	for _, body := range tests {
		m := New()
		results, err := m.ScanPerRequest(makeHTTPCtx("/assets/app.js", "application/javascript", body), &modkit.ScanContext{})
		require.NoError(t, err)
		assert.Empty(t, results, body)
	}
}

func TestScanPerRequest_GenericPublicValueIsNotEnough(t *testing.T) {
	t.Parallel()
	m := New()
	body := `const config = {NEXT_PUBLIC_API_KEY: "browser-client-key"};`
	results, err := m.ScanPerRequest(makeHTTPCtx("/app.js", "application/javascript", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_DocumentationAssignmentIsIgnored(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<pre>NEXT_PUBLIC_API_SECRET: "ghp_abcdef` + `ghijklmnop` + `qrstuvwxyz` + `123456"</pre>`
	results, err := m.ScanPerRequest(makeHTTPCtx("/docs/environment", "text/html", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_DotenvSyntaxRequiresDotenvPath(t *testing.T) {
	t.Parallel()
	m := New()
	body := "Configure the app with:\nPASSWORD=J7q9P2m4R8t6V3x1\n"
	results, err := m.ScanPerRequest(makeHTTPCtx("/examples/setup.txt", "text/plain", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_ErrorPageCannotEstablishExposure(t *testing.T) {
	t.Parallel()
	m := New()
	body := "STRIPE_KEY=sk_live_ab" + "cdef123456" + "7890\n"
	ctx := makeHTTPStatusCtx("/.env", "text/plain", body, 404, "Not Found")
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestScanPerRequest_PlaceholderValueIsIgnored(t *testing.T) {
	t.Parallel()
	m := New()
	body := "PASSWORD=your_password_here\n"
	results, err := m.ScanPerRequest(makeHTTPCtx("/.env.production", "text/plain", body), &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// TestScanPerRequest_Benign verifies a body without any secret indicators is
// not flagged.
func TestScanPerRequest_Benign(t *testing.T) {
	t.Parallel()
	m := New()
	body := `<html><body>Welcome to the homepage</body></html>`
	ctx := makeHTTPCtx("/", "text/html", body)
	results, err := m.ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	assert.Empty(t, results)
}

// One representative value per family in knownSecretPatterns / the public lists.
// Shared by the disjointness guard and the end-to-end tests so a value can never
// be tightened in one place and left stale in the other.
//
// stripeRestrictedLiveKey is a Stripe RESTRICTED live key — a scoped SECRET key,
// not a publishable one. Stripe's guidance is explicit that neither `sk_live_`
// nor `rk_live_` may go into a variable a framework bundles into the client.
const (
	stripeRestrictedLiveKey  = "rk_live_" + "51H8xQ2mLp" + "7RtY4vNb3K" + "wZ6dJ9sFgA"
	stripeSecretLiveKey      = "sk_live_" + "51H8xQ2mLp" + "7RtY4vNb3K" + "wZ6dJ9sFgA"
	stripePublishableLiveKey = "pk_live_" + "51H8xQ2mLp" + "7RtY4vNb3K" + "wZ6dJ9sFgA"
	stripePublishableTestKey = "pk_test_" + "51H8xQ2mLp" + "7RtY4vNb3K" + "wZ6dJ9sFgA"
	githubPAT                = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	slackBotToken            = "xoxb-24938" + "27450-2492" + "837401-Ff8" + "3jdkeExamp" + "le920Slack"
	googleBrowserAPIKey      = "AIzaSyB1a2b3c4d5e6f7g8h9i0jklmnopqrstuv"
	googleOAuthClientID      = "111111111111-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.apps.googleusercontent.com"
	firebaseWebAppID         = "1:111111111111:web:a1b2c3d4e5f6a7b8"
	recaptchaSiteKey         = "6LfExampleSiteKeyValue0000000000000000AB"
	branchLiveKey            = "key_live_hK4mZq8tRw2vNp6xLb3yFc9sJd5g"
	branchTestKey            = "key_test_hK4mZq8tRw2vNp6xLb3yFc9sJd5g"
	braintreeTokenizationKey = "production_qw83hs21_kd94mzp67vbx2r"
	salesforceConsumerKey    = "3MVG9fTLmJ60pJ5KxSmtobJLmmeX3Yr9sJrDKgSb2xhl1znSnx8kH1.e7BbBcInj7bhGxZij011PyyEMAP23X"
)

// TestKnownValueListsAreDisjoint is the structural guard behind assessCredential's
// ordering: no value may be classified as both a known secret and publishable. An
// entry that lands in both used to be resolved in the public list's favour and
// dropped outright, which is how a bundled Stripe restricted live key went
// unreported.
func TestKnownValueListsAreDisjoint(t *testing.T) {
	t.Parallel()
	for _, v := range []string{
		stripeRestrictedLiveKey, stripeSecretLiveKey, githubPAT, slackBotToken,
		stripePublishableLiveKey, stripePublishableTestKey, googleBrowserAPIKey,
		googleOAuthClientID, firebaseWebAppID, recaptchaSiteKey,
		branchLiveKey, branchTestKey, braintreeTokenizationKey, salesforceConsumerKey,
	} {
		var secretLabel string
		for _, pattern := range knownSecretPatterns {
			if pattern.re.MatchString(v) {
				secretLabel = pattern.name
				break
			}
		}
		if secretLabel != "" && isKnownPublicValue(v) {
			t.Errorf("%q is classified as both %q and publishable — assessCredential would have to pick one", v, secretLabel)
		}
	}
}

// TestScanPerRequest_StripeRestrictedKeyIsReported pins the regression: a
// restricted live key bundled into a public framework variable is a leaked secret.
func TestScanPerRequest_StripeRestrictedKeyIsReported(t *testing.T) {
	t.Parallel()
	body := `const cfg = {NEXT_PUBLIC_STRIPE_KEY: "` + stripeRestrictedLiveKey + `"};`
	ctx := makeHTTPCtx("/_next/static/chunk.js", "application/javascript", body)
	results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
	require.NoError(t, err)
	require.NotEmpty(t, results, "a bundled rk_live_ restricted key must be reported")
	assert.Equal(t, severity.High, results[0].Info.Severity)
	assert.Equal(t, "Stripe secret key", results[0].Metadata["credential_class"])
}

// TestScanPerRequest_PublicBrowserKeysAreNotCredentials covers the families that
// a front end must ship. Each is long and high-entropy enough to reach the
// "unrecognized high-entropy key" branch, so only the public list keeps them out.
func TestScanPerRequest_PublicBrowserKeysAreNotCredentials(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct{ name, value string }{
		{"recaptcha site key", recaptchaSiteKey},
		{"branch.io key", branchLiveKey},
		{"braintree tokenization key", braintreeTokenizationKey},
		{"salesforce consumer key", salesforceConsumerKey},
		{"stripe publishable key", stripePublishableLiveKey},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := `const cfg = {NEXT_PUBLIC_VENDOR_KEY: "` + tc.value + `"};`
			ctx := makeHTTPCtx("/_next/static/chunk.js", "application/javascript", body)
			results, err := New().ScanPerRequest(ctx, &modkit.ScanContext{})
			require.NoError(t, err)
			assert.Empty(t, results, "%s is public by design and must not be reported", tc.name)
		})
	}
}
