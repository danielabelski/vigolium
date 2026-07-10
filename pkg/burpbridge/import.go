package burpbridge

import (
	"context"
	"fmt"

	"github.com/vigolium/vigolium/pkg/database"
	"github.com/vigolium/vigolium/pkg/httpmsg"
)

const importBatchSize = 200

// RecordUpserter is the database operation needed by the bridge importer.
// database.Repository implements it directly.
type RecordUpserter interface {
	UpsertSnapshotRecord(context.Context, *httpmsg.HttpRequestResponse, string, string) (string, string, error)
}

type ImportResult struct {
	Matched   int64    `json:"matched"`
	Selected  int      `json:"selected"`
	Inserted  int      `json:"inserted"`
	Updated   int      `json:"updated"`
	Unchanged int      `json:"unchanged"`
	Skipped   int      `json:"skipped"`
	Oversized int      `json:"oversized"`
	Errors    []string `json:"errors,omitempty"`
}

func (r ImportResult) Stored() int { return r.Inserted + r.Updated + r.Unchanged }

// ImportIntoRepository copies the selected live Proxy history into the
// database. It pages the listener so temporary refs remain inspectable, and
// uses the snapshot upsert path so repeated imports are idempotent while a
// changed response refreshes the existing row.
func ImportIntoRepository(
	ctx context.Context,
	client *Client,
	repo RecordUpserter,
	query Query,
	projectUUID string,
) (ImportResult, error) {
	result := ImportResult{}
	query.ProjectUUID = projectUUID
	query.IncludeRaw = false
	if query.Location == "" {
		query.Location = "proxy_history"
	}

	nextOffset := max(query.Offset, 0)
	remaining := query.Limit
	for {
		pageSize := importBatchSize
		if remaining > 0 {
			pageSize = min(pageSize, remaining)
		}
		pageQuery := query
		pageQuery.Offset = nextOffset
		pageQuery.Limit = pageSize
		page, err := client.Query(ctx, pageQuery)
		if err != nil {
			return result, err
		}
		if result.Matched == 0 {
			result.Matched = page.Total
		}
		if len(page.Records) == 0 {
			break
		}

		for _, summary := range page.Records {
			result.Selected++
			inspection, err := client.InspectWithLimit(ctx, summary.UUID, projectUUID, MaxImportBytes)
			if err != nil {
				result.Skipped++
				result.addError(fmt.Sprintf("%s: %v", summary.URL, err))
				continue
			}
			if inspection.RequestTruncated || inspection.ResponseTruncated {
				result.Skipped++
				result.Oversized++
				continue
			}
			rr, err := database.RecordToHttpRequestResponse(inspection.Record)
			if err != nil {
				result.Skipped++
				result.addError(fmt.Sprintf("%s: %v", summary.URL, err))
				continue
			}
			_, outcome, err := repo.UpsertSnapshotRecord(ctx, rr, Source, projectUUID)
			if err != nil {
				return result, fmt.Errorf("store Burp record %s: %w", summary.URL, err)
			}
			switch outcome {
			case "inserted":
				result.Inserted++
			case "updated":
				result.Updated++
			default:
				result.Unchanged++
			}
		}

		count := len(page.Records)
		nextOffset += count
		if remaining > 0 {
			remaining -= count
			if remaining <= 0 {
				break
			}
		}
		if page.Total > 0 && int64(nextOffset) >= page.Total {
			break
		}
	}
	return result, nil
}

func (r *ImportResult) addError(message string) {
	if len(r.Errors) < 10 {
		r.Errors = append(r.Errors, message)
	}
}
