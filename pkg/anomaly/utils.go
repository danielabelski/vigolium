package anomaly

import (
	"hash/crc32"
	"unsafe"
)

func checksumCRC32(s string) uint32 {
	checksum := crc32.ChecksumIEEE(s2b(s))
	return checksum
}

// func toLowerHeaders(header map[string][]string) map[string]string {
// 	if header == nil {
// 		return map[string]string{}
// 	}
// 	reformatHeaders := make(map[string]string, len(header)) // Pre-allocate map capacity
// 	for hn, hv := range header {
// 		if len(hv) > 0 {
// 			lowerHn := strings.ToLower(hn) // Minimize function calls within the loop
// 			reformatHeaders[lowerHn] = hv[0]
// 		}
// 	}
// 	return reformatHeaders
// }

// func toLowerHeaders2(header map[string]string) map[string]string {
// 	if header == nil {
// 		return map[string]string{}
// 	}
// 	reformatHeaders := make(map[string]string, len(header)) // Pre-allocate map capacity
// 	for hn, hv := range header {
// 		lowerHn := strings.ToLower(hn) // Minimize function calls within the loop
// 		reformatHeaders[lowerHn] = hv
// 	}
// 	return reformatHeaders
// }

func convertMap(inputMap map[string]string) map[string][]string {
	if inputMap == nil {
		return map[string][]string{}
	}
	outputMap := make(map[string][]string, len(inputMap)) // Pre-allocate map capacity
	for k, v := range inputMap {
		outputMap[k] = []string{v}
	}
	return outputMap
}

func b2s(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}

func s2b(str string) []byte {
	if str == "" {
		return nil
	}
	return unsafe.Slice(unsafe.StringData(str), len(str))
}
