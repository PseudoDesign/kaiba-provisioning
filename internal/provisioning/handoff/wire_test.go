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

func TestCanonicalIntegerSpellings(t *testing.T) {
	for _, raw := range []string{`{"revision":1}`, `{"revision":1.0}`, `{"revision":1e0}`, `{"revision":0.1e1}`} {
		got, err := Canonical([]byte(raw))
		if err != nil || string(got) != `{"revision":1}` {
			t.Fatalf("%s: %s %v", raw, got, err)
		}
	}
	got, err := Canonical([]byte(`{"generation":-0}`))
	if err != nil || string(got) != `{"generation":0}` {
		t.Fatalf("negative zero: %s %v", got, err)
	}
	for _, raw := range []string{`{"revision":1.5}`, `{"revision":-1}`, `{"revision":9007199254740993}`, `{"revision":9.007199254740992e15}`, `{"revision":1e9999}`} {
		if _, err := Canonical([]byte(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
}
