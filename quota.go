package mega

import (
	"bytes"
	"encoding/json"
	"strconv"
)

// MEGA serializes some quota counters as decimal strings on free accounts.
// Keep the public numeric fields while accepting both supported wire shapes.
func (q *QuotaResp) UnmarshalJSON(data []byte) error {
	type plain QuotaResp
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || fields == nil {
		return EBADRESP
	}
	for _, required := range []string{"mstrg", "cstrg"} {
		value, ok := fields[required]
		if !ok || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return EBADRESP
		}
	}
	for _, name := range []string{"mstrg", "cstrg", "mxfer", "caxfer", "csxfer", "utype", "suntil"} {
		raw, ok := fields[name]
		if !ok {
			continue
		}
		raw = bytes.TrimSpace(raw)
		if len(raw) > 0 && raw[0] == '"' {
			var value string
			if json.Unmarshal(raw, &value) != nil {
				return EBADRESP
			}
			if _, err := strconv.ParseUint(value, 10, 64); err != nil {
				return EBADRESP
			}
			fields[name] = json.RawMessage(value)
		}
	}
	normalized, err := json.Marshal(fields)
	if err != nil {
		return EBADRESP
	}
	var result plain
	if json.Unmarshal(normalized, &result) != nil {
		return EBADRESP
	}
	*q = QuotaResp(result)
	return nil
}
