package salesforce

import (
	"encoding/json"
	"fmt"
	"strings"
)

// descApexExecute is the Aura action descriptor that invokes an @AuraEnabled
// Apex method (aura://ApexActionController/ACTION$execute). Unlike the
// serviceComponent controllers used by getConfigData/getItems, this dispatches
// into arbitrary server-side Apex, so a guest that can drive it has a pivot for
// SSRF, data exfiltration, DML and more (per the sf_apex_execution research).
const descApexExecute = "aura://ApexActionController/ACTION$execute"

// BuildApexExecute returns an ApexActionController.execute message that invokes
// namespace.classname.method with no arguments. It is used strictly as a probe
// with a benign, read-only method (or a bogus one for the negative control) — no
// arguments are ever sent, so it can never carry a side-effecting payload.
//
// Every component is JSON-marshalled so a crafted name cannot break out of the
// JSON string. The wire shape matches the documented guest-Apex technique
// (cacheable/isContinuation present, method args omitted for a no-arg method).
func BuildApexExecute(namespace, classname, method string) string {
	ns, _ := json.Marshal(namespace)
	cn, _ := json.Marshal(classname)
	mt, _ := json.Marshal(method)
	return fmt.Sprintf(
		`{"actions":[{"id":"209;a","descriptor":"%s","callingDescriptor":"UNKNOWN","params":{"namespace":%s,"classname":%s,"method":%s,"cacheable":false,"isContinuation":false}}]}`,
		descApexExecute, string(ns), string(cn), string(mt),
	)
}

// HasSuccessAction reports whether any action in the batch reached state SUCCESS.
// For an Apex-execution probe a SUCCESS state means the server-side method
// actually ran (returnValue may legitimately be null for a void/empty method) —
// distinct from SuccessReturnValue, which additionally requires a populated
// return value and is the right oracle for the data-exposure modules.
func (r AuraResponse) HasSuccessAction() bool {
	for _, a := range r.Actions {
		if strings.EqualFold(a.State, "SUCCESS") {
			return true
		}
	}
	return false
}
