package burpbridge

import (
	"testing"
	"time"

	"github.com/vigolium/vigolium/pkg/database"
)

func TestMergePageSortsAndPaginatesAcrossSources(t *testing.T) {
	now := time.Now()
	local := []*database.HTTPRecord{{UUID: "db-1", Source: "db", CreatedAt: now.Add(-time.Minute)}}
	live := []*database.HTTPRecord{{UUID: "burp:1", Source: Source, CreatedAt: now}}

	records, total := MergePage(local, live, 1, 1, 0, 1, "created_at", false)
	if total != 2 || len(records) != 1 || records[0].UUID != "burp:1" {
		t.Fatalf("total=%d records=%+v", total, records)
	}
}

func TestMergePagePrefersLiveCopyOfImportedRequest(t *testing.T) {
	now := time.Now()
	local := []*database.HTTPRecord{{
		UUID: "db-1", Source: Source, RequestHash: "same-request", CreatedAt: now.Add(-time.Minute),
	}}
	live := []*database.HTTPRecord{{
		UUID: UUIDPrefix + "1", Source: Source, RequestHash: "same-request", CreatedAt: now,
	}}

	records, total := MergePage(local, live, 1, 1, 0, 10, "created_at", false)
	if total != 1 || len(records) != 1 || records[0].UUID != UUIDPrefix+"1" {
		t.Fatalf("total=%d records=%+v", total, records)
	}
}
