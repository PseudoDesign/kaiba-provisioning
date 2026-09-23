package pilotexport

import (
	"encoding/json"
	"sort"
)

func stableRetained(r retained) ([]byte, error) { sort.Strings(r.Evidence); return json.Marshal(r) }
