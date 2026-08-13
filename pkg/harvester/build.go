package harvester

// SourceKeys carries the API credentials for the keyed harvester sources.
// A source whose credential is empty is skipped by BuildSources rather than
// constructed with no key, mirroring the scan runner's behaviour.
type SourceKeys struct {
	URLScan    string
	VirusTotal string
}

// BuildSources constructs the harvester Source list for the named sources,
// applying proxyURL to each and skipping any keyed source (urlscan/virustotal)
// whose credential is empty. Names not recognised as a source are ignored.
//
// This is the single builder shared by the scan runner's external-harvest phase
// (buildExternalHarvesterSource) and the `vigolium kit harvest` utility, so the
// source set the utility offers can never drift from the one the scanner runs.
func BuildSources(names []string, keys SourceKeys, proxyURL string) []Source {
	var sources []Source
	for _, name := range names {
		switch name {
		case "wayback":
			sources = append(sources, NewWaybackSource(proxyURL))
		case "commoncrawl":
			sources = append(sources, NewCommonCrawlSource(proxyURL))
		case "arquivo":
			sources = append(sources, NewArquivoSource(proxyURL))
		case "alienvault":
			sources = append(sources, NewAlienVaultSource(proxyURL))
		case "urlscan":
			if keys.URLScan != "" {
				sources = append(sources, NewURLScanSource(keys.URLScan, proxyURL))
			}
		case "virustotal":
			if keys.VirusTotal != "" {
				sources = append(sources, NewVirusTotalSource(keys.VirusTotal, proxyURL))
			}
		}
	}
	return sources
}
