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
