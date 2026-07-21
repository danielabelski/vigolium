package cli

import "testing"

func TestBurpBridgeURLFlagsAreAvailable(t *testing.T) {
	if serverCmd.Flags().Lookup("burp-bridge-url") == nil {
		t.Fatal("vigolium server is missing --burp-bridge-url")
	}
	if trafficCmd.Flags().Lookup("burp-bridge-url") == nil {
		t.Fatal("vigolium traffic is missing --burp-bridge-url")
	}
	if importCmd.Flags().Lookup("burp-bridge-url") == nil {
		t.Fatal("vigolium import is missing --burp-bridge-url")
	}
	if trafficCmd.Flags().Lookup("save-to-vigolium-db") == nil {
		t.Fatal("vigolium traffic is missing --save-to-vigolium-db")
	}
	if trafficCmd.Flags().Lookup("save-to-burp") == nil {
		t.Fatal("vigolium traffic is missing --save-to-burp")
	}
	if replayCmd.Flags().Lookup("burp-bridge-url") == nil {
		t.Fatal("vigolium replay is missing --burp-bridge-url")
	}
	if replayCmd.Flags().Lookup("save-to-burp") == nil {
		t.Fatal("vigolium replay is missing --save-to-burp")
	}
}

// TestBurpSendFlagsAreAvailable guards the new Burp-engine send/push flags on
// replay, fuzz, and finding so a rename or dropped registration is caught.
func TestBurpSendFlagsAreAvailable(t *testing.T) {
	for _, flag := range []string{"send-via-burp", "http-mode", "send-timeout", "to-repeater", "repeater-tab", "to-organizer", "notes", "highlight"} {
		if replayCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("vigolium replay is missing --%s", flag)
		}
	}
	for _, flag := range []string{"send-via-burp", "burp-bridge-url", "http-mode", "send-timeout", "matches-to-organizer"} {
		if fuzzCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("vigolium fuzz is missing --%s", flag)
		}
	}
	for _, flag := range []string{"push-to-burp", "to-repeater", "send-via-burp", "http-mode", "burp-bridge-url"} {
		if findingCmd.Flags().Lookup(flag) == nil {
			t.Fatalf("vigolium finding is missing --%s", flag)
		}
	}
}
