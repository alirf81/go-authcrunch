// Copyright 2022 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package oauth

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// RefreshToken performs refresh token.
func (b *IdentityProvider) RefreshToken(r *requests.Request) error {

	r.Response.Code = http.StatusBadRequest
	refreshTokenCookie, err1 := r.Upstream.Request.Cookie("refresh_token")
	if err1 != nil {
		b.logger.Debug(
			"failed to read refresh token from cookie",
			zap.String("session_id", r.Upstream.SessionID),
			zap.String("request_id", r.ID),
			zap.Error(err1),
		)
		return errors.ErrIdentityProviderOauthReadRefreshTokenFailed.WithArgs(err1)
	}

	var accessToken map[string]interface{}
	var err error
	accessToken, err = b.fetchRefreshedAccessToken(refreshTokenCookie.Value)
	switch b.config.Driver {
	case "facebook":
		return errors.ErrIdentityProviderOauthRefreshTokenNotImplemented
	default:
		accessToken, err = b.fetchRefreshedAccessToken(refreshTokenCookie.Value)
	}
	if err != nil {
		b.logger.Debug(
			"failed refreshing OAuth 2.0 access token from the authorization server",
			zap.String("session_id", r.Upstream.SessionID),
			zap.String("request_id", r.ID),
			zap.Error(err),
		)
		return errors.ErrIdentityProviderOauthRefreshAccessTokenFailed.WithArgs(err)
	}
	b.logger.Debug(
		"refreshed OAuth 2.0 authorization server access token",
		zap.String("request_id", r.ID),
		zap.Any("token", accessToken),
	)

	var m map[string]interface{}

	switch b.config.Driver {
	case "github", "gitlab", "facebook":
		m, err = b.fetchClaims(accessToken)
		if err != nil {
			return errors.ErrIdentityProviderOauthFetchClaimsFailed.WithArgs(err)
		}
	default:
		m, err = b.validateAccessToken("", accessToken)
		if err != nil {
			return errors.ErrIdentityProviderOauthValidateAccessTokenFailed.WithArgs(err)
		}
	}

	// Fetch user info.
	if err := b.fetchUserInfo(accessToken, m); err != nil {
		b.logger.Debug(
			"failed fetching user info",
			zap.String("request_id", r.ID),
			zap.Error(err),
		)
	}

	// Fetch subsequent user info, e.g. user groups.
	if err := b.fetchUserGroups(accessToken, m); err != nil {
		b.logger.Debug(
			"failed fetching user groups",
			zap.String("request_id", r.ID),
			zap.Error(err),
		)
	}

	if b.config.IdentityTokenCookieEnabled {
		if v, exists := accessToken["id_token"]; exists {
			r.Response.IdentityTokenCookie.Enabled = true
			r.Response.IdentityTokenCookie.Name = b.config.IdentityTokenCookieName
			r.Response.IdentityTokenCookie.Payload = v.(string)
		}
	}

	// Add refresh token
	if accessToken != nil {
		if _, exists := accessToken["refresh_token"]; exists {
			r.RefreshToken = accessToken["refresh_token"].(string)
		} else {
			b.logger.Warn("cannot find refresh token in OAtuh 2.0 response")
		}
	}

	r.Response.Payload = m
	r.Response.Code = http.StatusOK
	b.logger.Debug(
		"decoded claims from OAuth 2.0 authorization server access token",
		zap.String("request_id", r.ID),
		zap.Any("claims", m),
	)
	return nil
}

func (b *IdentityProvider) fetchRefreshedAccessToken(refreshToken string) (map[string]interface{}, error) {
	params := url.Values{}
	params.Set("client_id", b.config.ClientID)
	params.Set("client_secret", b.config.ClientSecret)
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", refreshToken)

	cli := &http.Client{
		Timeout: time.Second * 10,
	}

	cli, err := b.newBrowser()
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest("POST", b.tokenURL, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}

	// Adjust !!!
	if b.enableAcceptHeader {
		req.Header.Set("Accept", "application/json")
	}

	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Add("Content-Length", strconv.Itoa(len(params.Encode())))

	resp, err := cli.Do(req)
	if err != nil {
		return nil, err
	}

	respBody, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	b.logger.Debug(
		"OAuth 2.0 access token response received",
		zap.Any("body", respBody),
	)

	data := make(map[string]interface{})
	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, err
	}

	b.logger.Debug(
		"OAuth 2.0 access token response decoded",
		zap.Any("body", data),
	)

	if _, exists := data["error"]; exists {
		if v, exists := data["error_description"]; exists {
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailedDetailed.WithArgs(data["error"].(string), v.(string))
		}
		switch data["error"].(type) {
		case string:
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailed.WithArgs(data["error"].(string))
		default:
			return nil, errors.ErrIdentityProviderOauthGetAccessTokenFailed.WithArgs(data["error"])
		}
	}

	for k := range b.requiredTokenFields {
		if _, exists := data[k]; !exists {
			return nil, errors.ErrIdentityProviderAuthorizationServerResponseFieldNotFound.WithArgs(k)
		}
	}
	return data, nil
}
