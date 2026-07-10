package burpbridge

import (
	"cmp"
	"sort"
	"strings"

	"github.com/vigolium/vigolium/pkg/database"
)

// MergePage combines already-sorted leading records from the database and
// Burp, applies the shared sort order, then returns the requested global page.
func MergePage(
	local, live []*database.HTTPRecord,
	localTotal, liveTotal int64,
	offset, limit int,
	sortBy string,
	ascending bool,
) ([]*database.HTTPRecord, int64) {
	combined := make([]*database.HTTPRecord, 0, len(local)+len(live))
	combined = append(combined, local...)
	// A record explicitly imported from the bridge also remains present in live
	// Proxy history. Prefer the current live row when its raw-request hash
	// matches a persisted row so enabling the bridge does not show two copies.
	localByHash := make(map[string]int, len(local))
	for i, record := range local {
		if record.RequestHash != "" {
			localByHash[record.RequestHash] = i
		}
	}
	duplicates := int64(0)
	for _, record := range live {
		if i, ok := localByHash[record.RequestHash]; record.RequestHash != "" && ok {
			combined[i] = record
			delete(localByHash, record.RequestHash)
			duplicates++
			continue
		}
		combined = append(combined, record)
	}
	sort.SliceStable(combined, func(i, j int) bool {
		order := compareRecords(combined[i], combined[j], sortBy)
		if order == 0 {
			order = strings.Compare(combined[i].UUID, combined[j].UUID)
		}
		if ascending {
			return order < 0
		}
		return order > 0
	})
	from := min(max(offset, 0), len(combined))
	to := len(combined)
	if limit > 0 {
		to = min(to, from+limit)
	}
	return combined[from:to], max(0, localTotal+liveTotal-duplicates)
}

func compareRecords(a, b *database.HTTPRecord, sortBy string) int {
	switch sortBy {
	case "uuid":
		return strings.Compare(a.UUID, b.UUID)
	case "method":
		return strings.Compare(a.Method, b.Method)
	case "path":
		return strings.Compare(a.Path, b.Path)
	case "status", "status_code":
		return cmp.Compare(a.StatusCode, b.StatusCode)
	case "response_time", "time":
		return cmp.Compare(a.ResponseTimeMs, b.ResponseTimeMs)
	case "source":
		return strings.Compare(a.Source, b.Source)
	case "risk", "risk_score":
		return cmp.Compare(a.RiskScore, b.RiskScore)
	case "url":
		return strings.Compare(a.URL, b.URL)
	case "sent", "sent_at":
		return a.SentAt.Compare(b.SentAt)
	default:
		return a.CreatedAt.Compare(b.CreatedAt)
	}
}
