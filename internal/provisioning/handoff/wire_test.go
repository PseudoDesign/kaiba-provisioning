package handoff

import (
	"testing"
)

func TestCanonical(t *testing.T) {
	for _, tc := range []struct{ in, out string }{{`{"z":1,"a":"<>&\u2028","b":"\b"}`, "{\"a\":\"<>&\u2028\",\"b\":\"\\b\",\"z\":1}"}, {`{"\ue000":0,"\ud800\udc00":1}`, "{\"𐀀\":1,\"\":0}"}} {
		b, e := Canonical([]byte(tc.in))
		if e != nil || string(b) != tc.out {
			t.Fatalf("got %q %v", b, e)
		}
	}
	for _, s := range []string{`{"a":1,"a":2}`, `{"a":"\ud800"}`, `{"a":9007199254740992}`, `{} {}`, `{"a":NaN}`} {
		if _, e := Canonical([]byte(s)); e == nil {
			t.Fatalf("accepted %s", s)
		}
	}
}
