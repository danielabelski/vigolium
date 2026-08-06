package burpscope

import (
	"github.com/vigolium/vigolium/pkg/httpmsg"
	"github.com/vigolium/vigolium/pkg/input/formats"
	"go.uber.org/zap"
)

// Format implements formats.Format for Burp Suite scope exports, emitting one
// GET request per seed URL the scope's include rules resolve to.
type Format struct {
	opts formats.InputFormatOptions
}

// New creates a new burpscope Format parser.
func New() *Format {
	return &Format{}
}

var _ formats.Format = &Format{}

// Name returns the format name.
func (f *Format) Name() string { return "burpscope" }

// SetOptions sets generic format options.
func (f *Format) SetOptions(options formats.InputFormatOptions) {
	f.opts = options
}

// Parse expands the scope file and calls callback with a GET request per
// derived target.
func (f *Format) Parse(input string, callback formats.ParseReqRespCallback) error {
	res, err := TargetURLs(input)
	if err != nil {
		return err
	}
	zap.L().Info("burpscope: expanded scope file", zap.String("file", input), zap.String("summary", res.Summary()))

	for _, u := range res.URLs {
		rr, err := httpmsg.GetRawRequestFromURL(u)
		if err != nil {
			zap.L().Warn("burpscope: could not build request from scope target", zap.String("url", u), zap.Error(err))
			continue
		}
		if !callback(rr) {
			return nil
		}
	}
	return nil
}

// Count returns the number of seed URLs the scope file yields.
func (f *Format) Count(input string) (int64, error) {
	res, err := TargetURLs(input)
	if err != nil {
		return 0, err
	}
	return int64(len(res.URLs)), nil
}
