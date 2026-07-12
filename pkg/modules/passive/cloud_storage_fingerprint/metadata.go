package cloud_storage_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-fingerprint"
	ModuleName  = "Cloud Storage Fingerprint"
	ModuleShort = "Detects S3, GCS, and Azure Blob Storage endpoints in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The app serves content from or links to a cloud object-storage backend (S3, GCS, or Azure Blob), identified passively from a request host that is a raw storage endpoint (e.g. bucket.s3.amazonaws.com) or a storage URL embedded in the response body. Provider headers (x-amz-*, x-goog-*, x-ms-*) and the Server header are treated as corroboration only — on their own they merely reveal that content is served through a cloud CDN/store and never name a bucket, so they do not raise a finding. Informational fingerprint that discloses where assets live.


**How it's exploited:** An attacker uses the disclosed bucket and account names to probe the endpoint for misconfigurations - public read/write, listable buckets, or broad ACLs - leading to data exposure or tampering.

**Fix:** Lock down storage permissions: disable public access, enforce least-privilege ACLs, block listing, and serve assets via a CDN or signed URLs.`

	ModuleConfirmation = "Confirmed when a request host is a raw cloud storage endpoint or the response body embeds a bucket/account storage URL"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "fingerprint", "light"}
)
