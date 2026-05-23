package llm

import "context"

// Client is the interface all LLM backends implement. The sole implementation
// is the olium-backed adapter (see olium_client.go); the JS extension
// vigolium.agent.* API is the only consumer.
type Client interface {
	Complete(ctx context.Context, req CompletionRequest) (*CompletionResponse, error)
}
