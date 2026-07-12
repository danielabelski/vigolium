package discovery

import "testing"

func TestLooksLikeAPIEndpointPath(t *testing.T) {
	api := []string{
		"/rest/basket", "/rest/wallet/balance", "/api/BasketItems", "/api/Cards",
		"/rest/order-history", "/graphql", "/v1/users", "/v2/orders", "/rpc/call",
	}
	for _, p := range api {
		if !looksLikeAPIEndpointPath(p) {
			t.Errorf("expected API endpoint: %q", p)
		}
	}
	notAPI := []string{
		"", "relative/path", "/assets/i18n/en.json", "/main.js", "/styles.css",
		"/search", "/login", "/about", "/score-board", "/therapist/list",
		"/forest/trees", "/version", "/v/x",
	}
	for _, p := range notAPI {
		if looksLikeAPIEndpointPath(p) {
			t.Errorf("did not expect API endpoint: %q", p)
		}
	}
}
