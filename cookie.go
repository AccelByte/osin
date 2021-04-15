// Copyright (c) 2021 AccelByte Inc. All Rights Reserved.
// This is licensed software from AccelByte Inc, for limitations
// and restrictions contact your company contract manager.

package osin

import (
	"encoding/base64"
	"github.com/AccelByte/go-jose/json"
	"github.com/sirupsen/logrus"
	"net/http"
	"strings"
	"time"
)

// JWTPayload represents JWT payload to extract JWT expiration time
type JWTPayload struct {
	Expiration int64 `json:"exp"`
}

// AddTokenInCookie adds token cookie in the response header
func AddTokenInCookie(response *Response, token string, tokenType string) {
	expireAt := getExpirationTime(token)
	cookie := http.Cookie{
		Name:     tokenType,
		Value:    token,
		Expires:  expireAt,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteNoneMode,
		Path:     "/",
	}
	if v := cookie.String(); v != "" {
		response.Headers.Add("Set-Cookie", v)
	}
}

// getExpirationTime gets the expiration time of the given token
func getExpirationTime(jwt string) time.Time {
	jwtParts := strings.Split(jwt, ".")
	if len(jwtParts) != 3 {
		logrus.Warn("unable to get expiration time: token part is invalid")
		return time.Time{}
	}

	if l := len(jwtParts[1]) % 4; l > 0 {
		jwtParts[1] += strings.Repeat("=", 4-l)
	}

	decodedPayload, err := base64.StdEncoding.DecodeString(jwtParts[1])
	if err != nil {
		logrus.Warn("unable to get expiration time: unable to decode JWT payload: ", err)
		return time.Time{}
	}

	var jwtPayload JWTPayload
	err = json.Unmarshal(decodedPayload, &jwtPayload)

	if err != nil {
		logrus.Warn("unable to get expiration time: unable to unmarshal JWT payload ", err)
		return time.Time{}
	}

	return time.Unix(jwtPayload.Expiration, 0)
}
