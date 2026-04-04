package conformanceharness

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseFormPostAutoSubmit(t *testing.T) {
	html := `<!DOCTYPE html>
<html>
<head><title>Submit</title></head>
<body onload="document.forms[0].submit()">
<form method="post" action="https://rp.localhost/callback/alias-a">
<input type="hidden" name="code" value="abc123" />
<input type="hidden" name="state" value="xyz789" />
<input type="hidden" name="iss" value="https://issuer.test" />
</form>
</body>
</html>`

	actionURL, params, ok := parseFormPostAutoSubmit(html)
	if !ok {
		t.Fatalf("parseFormPostAutoSubmit() returned false")
	}
	if actionURL != "https://rp.localhost/callback/alias-a" {
		t.Fatalf("actionURL = %q, want https://rp.localhost/callback/alias-a", actionURL)
	}
	want := url.Values{
		"code":  {"abc123"},
		"state": {"xyz789"},
		"iss":   {"https://issuer.test"},
	}
	if diff := cmp.Diff(want, params); diff != "" {
		t.Fatalf("params mismatch (-want +got):\n%s", diff)
	}
}

func TestParseFormPostAutoSubmit_MethodCaseInsensitive(t *testing.T) {
	html := `<html><body><form method="POST" action="/callback"><input type="hidden" name="code" value="c" /></form></body></html>`

	actionURL, params, ok := parseFormPostAutoSubmit(html)
	if !ok {
		t.Fatalf("parseFormPostAutoSubmit() returned false")
	}
	if actionURL != "/callback" {
		t.Fatalf("actionURL = %q, want /callback", actionURL)
	}
	if params.Get("code") != "c" {
		t.Fatalf("code = %q, want %q", params.Get("code"), "c")
	}
}

func TestParseFormPostAutoSubmit_NoForm(t *testing.T) {
	_, _, ok := parseFormPostAutoSubmit(`<html><body><p>no form here</p></body></html>`)
	if ok {
		t.Fatalf("expected false for HTML without form")
	}
}

func TestParseFormPostAutoSubmit_GetFormIgnored(t *testing.T) {
	_, _, ok := parseFormPostAutoSubmit(`<html><body><form method="get" action="/callback"><input type="hidden" name="code" value="c" /></form></body></html>`)
	if ok {
		t.Fatalf("expected false for GET form")
	}
}

func TestParseFormPostAutoSubmit_NoAction(t *testing.T) {
	_, _, ok := parseFormPostAutoSubmit(`<html><body><form method="post"><input type="hidden" name="code" value="c" /></form></body></html>`)
	if ok {
		t.Fatalf("expected false for form without action")
	}
}

func TestIsHTMLFormPostResponse(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{name: "html 200", statusCode: 200, contentType: "text/html; charset=utf-8", want: true},
		{name: "no form plain html", statusCode: 200, contentType: "text/html", want: true},
		{name: "json response", statusCode: 200, contentType: "application/json", want: false},
		{name: "not 200", statusCode: 302, contentType: "text/html", want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			rec.Header().Set("Content-Type", tc.contentType)
			rec.WriteHeader(tc.statusCode)
			rec.Write([]byte(`<html><body>test</body></html>`))

			resp := rec.Result()
			got := isHTMLFormPostResponse(resp)
			resp.Body.Close()

			if got != tc.want {
				t.Fatalf("isHTMLFormPostResponse() = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestIsFormPostAutoSubmitHTML(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{name: "double quotes", body: `<form method="post" action="/cb">`, want: true},
		{name: "single quotes", body: `<form method='post' action="/cb">`, want: true},
		{name: "no quotes", body: `<form method=post action=/cb>`, want: true},
		{name: "uppercase", body: `<FORM METHOD="POST" ACTION="/cb">`, want: true},
		{name: "no method", body: `<form action="/cb">`, want: false},
		{name: "get method", body: `<form method="get" action="/cb">`, want: false},
		{name: "empty", body: ``, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isFormPostAutoSubmitHTML(tc.body)
			if got != tc.want {
				t.Fatalf("isFormPostAutoSubmitHTML() = %t, want %t", got, tc.want)
			}
		})
	}
}
