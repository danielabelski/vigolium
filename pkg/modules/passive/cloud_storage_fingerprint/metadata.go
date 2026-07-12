package cloud_storage_fingerprint

import "github.com/vigolium/vigolium/pkg/types/severity"

const (
	ModuleID    = "cloud-storage-fingerprint"
	ModuleName  = "Cloud Storage Fingerprint"
	ModuleShort = "Detects S3, GCS, and Azure Blob Storage endpoints in HTTP responses"
)

var (
	ModuleDesc = `**What it means:** The app serves or links to cloud object-storage (S3, GCS, or Azure Blob), fingerprinted passively from a request host that is a raw storage endpoint or a storage URL in the response body. Provider headers (x-amz-*, x-goog-*, x-ms-*) corroborate but never name a bucket.

**How it's exploited:** An attacker uses the disclosed bucket and account names to probe for misconfigurations — public read/write, listable buckets, or broad ACLs — exposing or tampering with data.

**Fix:** Lock down storage permissions: disable public access, enforce least-privilege ACLs, block listing, and serve assets via a CDN or signed URLs.`

	ModuleConfirmation = "Confirmed when a request host is a raw cloud storage endpoint or the response body embeds a bucket/account storage URL"
	ModuleSeverity     = severity.Info
	ModuleConfidence   = severity.Certain
	ModuleTags         = []string{"cloud", "fingerprint", "light"}
)
