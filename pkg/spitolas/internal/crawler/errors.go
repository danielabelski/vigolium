package crawler

import "errors"

// ErrCrawlConditionNotMet is returned when crawl conditions are not satisfied.
// It is used to skip MAB updates when an action was not actually executed.
var ErrCrawlConditionNotMet = errors.New("crawl condition not met")
