package olium

// SetupDocsURL is the single provider/credential setup guide for every agent
// mode (autopilot, swarm, query, olium, audit). It is the one page that answers
// "how do I make the agent run" — API key, OAuth, Vertex service account, or a
// local OpenAI-compatible model.
//
// Kept here rather than in pkg/cli so the CLI hint, the `agent`/`olium` help
// text, and the TUI's in-session error pointer all cite the same URL. The TUI
// receives it through tui.Config (pkg/olium imports tui, not the reverse).
const SetupDocsURL = "https://docs.vigolium.com/getting-started/setup-agent"
