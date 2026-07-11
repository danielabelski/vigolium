package database

import (
	"context"
	"fmt"
	"time"
)

const maxAnalysisArtifactBytes = 32 * 1024 * 1024

// SaveAnalysisArtifactForRecord stores a content-addressed immutable artifact
// beside an existing HTTP record. Duplicate writes of the same record/kind/hash
// are idempotent.
func (r *Repository) SaveAnalysisArtifactForRecord(ctx context.Context, artifact *AnalysisArtifact) error {
	if artifact == nil || artifact.HTTPRecordUUID == "" || artifact.Kind == "" || artifact.SHA256 == "" {
		return fmt.Errorf("invalid analysis artifact")
	}
	if len(artifact.Content) == 0 {
		return fmt.Errorf("analysis artifact content is empty")
	}
	if len(artifact.Content) > maxAnalysisArtifactBytes {
		return fmt.Errorf("analysis artifact exceeds %d-byte limit", maxAnalysisArtifactBytes)
	}

	var owner struct {
		ProjectUUID string `bun:"project_uuid"`
		ScanUUID    string `bun:"scan_uuid"`
	}
	if err := r.db.NewSelect().Table("http_records").
		Column("project_uuid", "scan_uuid").
		Where("uuid = ?", artifact.HTTPRecordUUID).
		Scan(ctx, &owner); err != nil {
		return fmt.Errorf("resolve artifact record: %w", err)
	}

	artifact.ProjectUUID = defaultProjectUUID(owner.ProjectUUID)
	artifact.ScanUUID = owner.ScanUUID
	artifact.ByteLength = int64(len(artifact.Content))
	if artifact.CreatedAt.IsZero() {
		artifact.CreatedAt = time.Now()
	}
	_, err := r.db.NewInsert().Model(artifact).On("CONFLICT DO NOTHING").Exec(ctx)
	return err
}

// SaveAnalysisArtifact is the primitive-argument adapter used by input sources
// that deliberately avoid importing the database package in their interfaces.
func (r *Repository) SaveAnalysisArtifact(
	ctx context.Context,
	httpRecordUUID, kind, filename, mediaType, sha256 string,
	content []byte,
	metadata string,
) error {
	return r.SaveAnalysisArtifactForRecord(ctx, &AnalysisArtifact{
		HTTPRecordUUID: httpRecordUUID,
		Kind:           kind,
		Filename:       filename,
		MediaType:      mediaType,
		SHA256:         sha256,
		Content:        content,
		Metadata:       metadata,
	})
}
