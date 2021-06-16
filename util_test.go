package osin

import (
	"net/http"
	"net/url"
	"testing"
)

const (
	badAuthValue        = "Digest XHHHHHHH"
	blankAuthValue      = "Basic Og=="
	goodAuthValue       = "Basic dGVzdDp0ZXN0"
	goodBearerAuthValue = "Bearer BGFVTDUJDp0ZXN0"
)

func TestBasicAuth(t *testing.T) {
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b, err := CheckBasicAuth(r); b != nil || err != nil {
		t.Errorf("Validated basic auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", badAuthValue)
	b, err := CheckBasicAuth(r)
	if b != nil || err == nil {
		t.Errorf("Validated invalid auth")
		return
	}

	// with blank auth header
	r.Header.Set("Authorization", blankAuthValue)
	b, err = CheckBasicAuth(r)
	if b != nil || err == nil {
		t.Errorf("Validated blank auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", goodAuthValue)
	b, err = CheckBasicAuth(r)
	if b == nil || err != nil {
		t.Errorf("Could not extract basic auth")
		return
	}

	// check extracted auth data
	if b.Username != "test" || b.Password != "test" {
		t.Errorf("Error decoding basic auth")
	}
}

func TestGetClientAuth(t *testing.T) {

	urlWithSecret, _ := url.Parse("http://host.tld/path?client_id=xxx&client_secret=yyy")
	urlWithEmptySecret, _ := url.Parse("http://host.tld/path?client_id=xxx&client_secret=")
	urlNoSecret, _ := url.Parse("http://host.tld/path?client_id=xxx")

	headerNoAuth := make(http.Header)
	headerBadAuth := make(http.Header)
	headerBadAuth.Set("Authorization", badAuthValue)
	headerOKAuth := make(http.Header)
	headerOKAuth.Set("Authorization", goodAuthValue)
	headerBlankAuth := make(http.Header)
	headerBlankAuth.Set("Authorization", blankAuthValue)

	var tests = []struct {
		header           http.Header
		url              *url.URL
		allowQueryParams bool
		expectAuth       bool
	}{
		{headerNoAuth, urlWithSecret, true, true},
		{headerNoAuth, urlWithSecret, false, false},
		{headerNoAuth, urlWithEmptySecret, true, true},
		{headerNoAuth, urlWithEmptySecret, false, false},
		{headerNoAuth, urlNoSecret, true, false},
		{headerNoAuth, urlNoSecret, false, false},

		{headerBadAuth, urlWithSecret, true, true},
		{headerBadAuth, urlWithSecret, false, false},
		{headerBadAuth, urlWithEmptySecret, true, true},
		{headerBadAuth, urlWithEmptySecret, false, false},
		{headerBadAuth, urlNoSecret, true, false},
		{headerBadAuth, urlNoSecret, false, false},

		{headerBlankAuth, urlWithSecret, true, true},
		{headerBlankAuth, urlWithSecret, false, false},
		{headerBlankAuth, urlWithEmptySecret, true, true},
		{headerBlankAuth, urlWithEmptySecret, false, false},
		{headerBlankAuth, urlNoSecret, true, false},
		{headerBlankAuth, urlNoSecret, false, false},

		{headerOKAuth, urlWithSecret, true, true},
		{headerOKAuth, urlWithSecret, false, true},
		{headerOKAuth, urlWithEmptySecret, true, true},
		{headerOKAuth, urlWithEmptySecret, false, true},
		{headerOKAuth, urlNoSecret, true, true},
		{headerOKAuth, urlNoSecret, false, true},
	}

	for _, tt := range tests {
		w := new(Response)
		r := &http.Request{Header: tt.header, URL: tt.url}
		r.ParseForm()
		auth := GetClientAuth(w, r, tt.allowQueryParams)
		if tt.expectAuth && auth == nil {
			t.Errorf("Auth should not be nil for %v", tt)
		} else if !tt.expectAuth && auth != nil {
			t.Errorf("Auth should be nil for %v", tt)
		}
	}

}

func TestBearerAuth(t *testing.T) {
	r := &http.Request{Header: make(http.Header)}

	// Without any header
	if b := CheckBearerAuth(r); b != nil {
		t.Errorf("Validated bearer auth without header")
	}

	// with invalid header
	r.Header.Set("Authorization", badAuthValue)
	b := CheckBearerAuth(r)
	if b != nil {
		t.Errorf("Validated invalid auth")
		return
	}

	// with valid header
	r.Header.Set("Authorization", goodBearerAuthValue)
	b = CheckBearerAuth(r)
	if b == nil {
		t.Errorf("Could not extract bearer auth")
		return
	}

	// check extracted auth data
	if b.Code != "BGFVTDUJDp0ZXN0" {
		t.Errorf("Error decoding bearer auth")
	}

	// extracts bearer auth from query string
	url, _ := url.Parse("http://host.tld/path?code=XYZ")
	r = &http.Request{URL: url}
	r.ParseForm()
	b = CheckBearerAuth(r)
	if b.Code != "XYZ" {
		t.Errorf("Error decoding bearer auth")
	}
}

func TestDecodeJWT_AccessToken(t *testing.T) {
	accessToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjlmZDRjZDVmOTkxY2ViZTMzMjM2MDVjZDEyZDNiOGJmZGZjNzNmYTQiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiaHR0cHM6Ly9hcGkuZGV2LmFjY2VsYnl0ZS5pbyIsImh0dHBzOi8vYXBpLmRldi5hY2NlbGJ5dGUuaW8vYmFzaWMiLCIiLCIiLCIiLCIiXSwiYmFucyI6W10sImNsaWVudF9pZCI6ImI4NTY5M2U0ODY1OTQ5YWQ4OGJkYTYwN2E1MzlmM2NkIiwiY291bnRyeSI6IklEIiwiZGlzcGxheV9uYW1lIjoiTWFyc2VsIDEiLCJleHAiOjE2MTc3ODMyMzgsImlhdCI6MTYxNzc3OTYzOCwiamZsZ3MiOjEsIm5hbWVzcGFjZSI6ImFjY2VsYnl0ZSIsIm5hbWVzcGFjZV9yb2xlcyI6bnVsbCwicGVybWlzc2lvbnMiOltdLCJyb2xlcyI6WyIyMjUxNDM4ODM5ZTk0OGQ3ODNlYzBlNTI4MWRhZjA1YiIsIjM2ZDc4ZDRhYTFiMDRkNDZiODIzODlkOWExMmU5YWViIl0sInNjb3BlIjoiYWNjb3VudCBjb21tZXJjZSBzb2NpYWwgcHVibGlzaGluZyBhbmFseXRpY3MiLCJzdWIiOiIzZjFkODdhMDQ3Yjk0NTM2Yjg1MTk5NTBkOGQ0NDhiMyJ9.Z2H7W2sNor-_SFCwWEAB-Rwh9Fjz6rOErZnY2Gj4TpnFQjS3T9atRDHt4Py2BF6urLcRZK6xOuL96-yR_WPxjjsj32WgZx_EhIsmWWhVQZFhVuuw1Ls3c2pohu2hAZ6cpzoHiNb_3MTAj0RSR0HoVUyiLlWa34IRvvOITbtBa2CJa1Uhvfx_ECN35C3GpUcmNbOBkZHnFRuQ6n6CfbzEEyLTC0P3DjRnMqK9FSn-E3EnCJV2dWZhzBMaLm4P610rVHb37_RxoKP8T706frkZiUE7Zb-j0AUuuQKBKAsfhVgkoEetyVHP0n25cpdNJu1c9WJG-gbaUCWZ9tnuKtVqDA"
	jwtPayload := decodeToken(accessToken)
	if int64(1617783238) != jwtPayload.Expiration {
		t.Errorf("Expected expirationTime is 1617866038, got %v", jwtPayload.Expiration)
	}
	if int64(1617779638) != jwtPayload.IssueAt {
		t.Errorf("Expected issueAt is 1617779638, got %v", jwtPayload.IssueAt)
	}
}

func TestDecodeJWT_RefreshToken(t *testing.T) {
	refreshToken := "eyJhbGciOiJSUzI1NiIsImtpZCI6IjlmZDRjZDVmOTkxY2ViZTMzMjM2MDVjZDEyZDNiOGJmZGZjNzNmYTQiLCJ0eXAiOiJKV1QifQ.eyJhdWQiOlsiaHR0cHM6Ly9hcGkuZGV2LmFjY2VsYnl0ZS5pbyIsImh0dHBzOi8vYXBpLmRldi5hY2NlbGJ5dGUuaW8vYmFzaWMiLCIiLCIiLCIiLCIiXSwiY2xpZW50X2lkIjoiYjg1NjkzZTQ4NjU5NDlhZDg4YmRhNjA3YTUzOWYzY2QiLCJleHAiOjE2MTc4NjYwMzgsImlhdCI6MTYxNzc3OTYzOCwibmFtZXNwYWNlIjoiYWNjZWxieXRlIiwic3ViIjoiM2YxZDg3YTA0N2I5NDUzNmI4NTE5OTUwZDhkNDQ4YjMifQ.jHBGVMY4tHSLzej39YanGla30_tl1lrQ867HGWA_Mx9n1y2hCbV_Oy6rJCEPI93qk7av-9AxI3RF_f5CPZRy7U3rvnKBEI_FImNg6_FUCaoUeGUv_y1R9d2F5zEj8XFs_qZuHtBhiUkYksJvo6teM4ctEv0DSq4lLyQtX1Mp2DA-GN0O8tnaeT2hWy_Te1P3nkjzyBrbeCM4cMw0ScQr-41F_DO6yJuOnSy32pE8eNDXwzNixe96Mrvfr7XnfSADqrCHVLoMrsQNpsrvXZ-MpJHLkViQ9d2PG6uSLlFUtrearApwCH4IlK6e3-Cx-QyF1q1FqJ36czvkD7crokfuvA"
	jwtPayload := decodeToken(refreshToken)
	if int64(1617866038) != jwtPayload.Expiration {
		t.Errorf("Expected expirationTime is 1617866038, got %v", jwtPayload.Expiration)
	}
	if int64(1617779638) != jwtPayload.IssueAt {
		t.Errorf("Expected issueAt is 1617779638, got %v", jwtPayload.IssueAt)
	}
}
