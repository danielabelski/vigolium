package iis_shortname_discovery

import (
	"fmt"
	"math"
	"strings"
)

// The 8.3 short-name generation and checksum routines below are ports of the
// algorithms in bitquark's shortscan (MIT licensed) and Tom Galvin's research:
//   - https://github.com/bitquark/shortscan (pkg/shortutil/shortutil.go)
//   - https://tomgalvin.uk/blog/gen/2015/06/09/filenames/
//
// They let us reconstruct the 8.3 short name Windows would generate for any
// candidate filename at scan time, so we can resolve a discovered fragment such
// as "WEBCON~1.CON" back to "web.config" by matching against a wordlist WITHOUT
// shipping a precomputed rainbow table.

// shortSpecialReplacer removes spaces/dots and maps the special characters
// : + , ; = [ ] to underscores, matching the Windows 2003 gen8dot3.c behaviour.
var shortSpecialReplacer = strings.NewReplacer(
	" ", "", ".", "",
	":", "_", "+", "_", ",", "_", ";", "_", "=", "_", "[", "_", "]", "_",
)

// gen8dot3 returns the Windows 8.3 short name parts (filename, extension) for a
// given long filename and extension (extension passed WITHOUT a leading dot).
// The boolean reports whether Windows would actually generate a short name at
// all (long name, long extension, or special characters present).
func gen8dot3(file, ext string) (required bool, file83, ext83 string) {
	fu := strings.ToUpper(file)
	fr := shortSpecialReplacer.Replace(fu)

	eu := strings.ToUpper(ext)
	er := shortSpecialReplacer.Replace(eu)

	required = len(file) > 8 || len(ext) > 3 || fu != fr || eu != er

	return required, fr[:min(len(fr), 6)], er[:min(len(er), 3)]
}

// checksum computes the modern (Windows Vista and later) 8.3 collision-avoidance
// checksum for a filename, returned as 4 uppercase hex digits. The input is the
// full filename including its extension (e.g. "Default.aspx").
func checksum(name string) string {
	var ck uint16
	for _, c := range name {
		ck = ck*0x25 + uint16(c)
	}

	t := int32(math.Abs(float64(int32(ck) * 314159269)))
	t -= int32(((uint64(t) * uint64(1152921497)) >> 60) * uint64(1000000007))

	ck = uint16(t)
	ck = (ck&0xf000)>>12 | (ck&0x0f00)>>4 | (ck&0x00f0)<<4 | (ck&0x000f)<<12

	return fmt.Sprintf("%04X", ck)
}

// checksumOriginal computes the older (Windows XP / Server 2003) 8.3 checksum
// for a filename, returned as 4 uppercase hex digits. Some legacy hosts still
// use this variant, so we index both.
func checksumOriginal(name string) string {
	if len(name) < 2 {
		return ""
	}

	ck := (uint16(name[0])<<8 + uint16(name[1])) & 0xffff
	for i := 2; i < len(name); i += 2 {
		if ck&1 == 1 {
			ck = 0x8000 + ck>>1 + uint16(name[i])<<8
		} else {
			ck = ck>>1 + uint16(name[i])<<8
		}
		if i+1 < len(name) {
			ck += uint16(name[i+1]) & 0xffff
		}
	}

	ck = (ck&0xf000)>>12 | (ck&0x0f00)>>4 | (ck&0x00f0)<<4 | (ck&0x000f)<<12

	return fmt.Sprintf("%04X", ck)
}
