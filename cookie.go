// Copyright (c) 2021 AccelByte Inc. All Rights Reserved.
// This is licensed software from AccelByte Inc, for limitations
// and restrictions contact your company contract manager.

package osin

import (
	"net/http"
	"time"
)

// AddTokenInCookie adds token cookie in the response header
func AddTokenInCookie(response *Response, token string, tokenType string, tokenExpiration int64) {
	cookie := http.Cookie{
		Name:     tokenType,
		Value:    token,
		Expires:  time.Unix(tokenExpiration, 0),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	}
	if v := cookie.String(); v != "" {
		response.Headers.Add("Set-Cookie", v)
	}
}
