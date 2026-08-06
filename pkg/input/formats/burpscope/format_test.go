package burpscope

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

func TestFormat_Name(t *testing.T) {
	assert.Equal(t, "burpscope", New().Name())
}

func TestFormat_ParseEmitsGETPerTarget(t *testing.T) {
	path := writeScope(t, twoHostScope)

	var got []*httpmsg.HttpRequestResponse
	require.NoError(t, New().Parse(path, func(rr *httpmsg.HttpRequestResponse) bool {
		got = append(got, rr)
		return true
	}))

	require.Len(t, got, 1)
	assert.Equal(t, "GET", got[0].Request().Method())
	assert.Equal(t, "www.example.com", got[0].Service().Host())
	assert.Equal(t, 443, got[0].Service().Port())
}

func TestFormat_ParseHonorsCallbackCancellation(t *testing.T) {
	path := writeScope(t, `{"target":{"scope":{"advanced_mode":true,"include":[
	  {"enabled":true,"file":"^/.*","host":"^a\\.example\\.com$","port":"^443$","protocol":"https"},
	  {"enabled":true,"file":"^/.*","host":"^b\\.example\\.com$","port":"^443$","protocol":"https"}
	]}}}`)

	count := 0
	require.NoError(t, New().Parse(path, func(*httpmsg.HttpRequestResponse) bool {
		count++
		return false
	}))
	assert.Equal(t, 1, count)
}

func TestFormat_ParseMissingFile(t *testing.T) {
	err := New().Parse(filepath.Join(t.TempDir(), "nope.json"), func(*httpmsg.HttpRequestResponse) bool { return true })
	assert.Error(t, err)
}

func TestFormat_Count(t *testing.T) {
	n, err := New().Count(writeScope(t, twoHostScope))
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	_, err = New().Count(filepath.Join(t.TempDir(), "nope.json"))
	assert.Error(t, err)
}
