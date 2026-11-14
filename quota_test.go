package mega

import (
	"encoding/json"
	"testing"
)

func TestQuotaDecimalStrings(t *testing.T) {
	for _, body := range []string{`{"mstrg":100,"cstrg":10,"mxfer":20,"caxfer":1,"csxfer":2}`, `{"mstrg":"100","cstrg":"10","mxfer":"20","caxfer":"1","csxfer":"2"}`} {
		var q QuotaResp
		if err := json.Unmarshal([]byte(body), &q); err != nil {
			t.Fatal(err)
		}
		if q.Mstrg != 100 || q.Caxfer+q.Csxfer != 3 {
			t.Fatal("quota counters differ")
		}
	}
}

func TestQuotaRejectsMissingCounters(t *testing.T) {
	for _, body := range []string{`null`, `{}`, `{"mstrg":100}`, `{"mstrg":null,"cstrg":0}`} {
		var q QuotaResp
		if err := json.Unmarshal([]byte(body), &q); err == nil {
			t.Fatal("accepted missing quota counters")
		}
	}
}
