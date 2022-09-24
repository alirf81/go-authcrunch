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

package authn

import (
	"context"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

type RefreshTokenResponse struct {
	Detail string `json:"detail"`
}

func (p *Portal) handleHTTPExternalRefreshToken(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, authMethod string) error {
	p.disableClientCache(w)

	authRealm, err := getEndpoint(r.URL.Path, "/"+authMethod+"/")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	authRealm = strings.Split(authRealm, "/")[0]

	rr.Upstream.Method = authMethod
	rr.Upstream.Realm = authRealm
	rr.Flags.Enabled = true
	rr.DisableRedirect = true

	p.logger.Debug(
		"External refresh token requested",
		zap.String("session_id", rr.Upstream.SessionID),
		zap.String("request_id", rr.ID),
		zap.String("base_url", rr.Upstream.BaseURL),
		zap.String("base_path", rr.Upstream.BasePath),
		zap.String("auth_method", rr.Upstream.Method),
		zap.String("auth_realm", rr.Upstream.Realm),
		zap.Any("request_path", r.URL.Path),
	)

	provider := p.getIdentityProviderByRealm(authRealm)
	if provider == nil {
		p.logger.Warn(
			"Refresh token failed",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("error", "identity provider not found"),
		)
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}
	err = provider.Request(operator.RefreshToken, rr)
	if err != nil {
		p.logger.Warn(
			"Refresh token failed",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.Error(err),
		)
		w.WriteHeader(http.StatusBadRequest)
		return nil
	}

	switch rr.Response.Code {
	case http.StatusBadRequest:
		w.WriteHeader(http.StatusBadRequest)
		return nil
	case http.StatusOK:
		p.logger.Debug(
			"Successful token refresh",
			zap.String("session_id", rr.Upstream.SessionID),
			zap.String("request_id", rr.ID),
			zap.String("auth_method", rr.Upstream.Method),
			zap.String("auth_realm", rr.Upstream.Realm),
			zap.Any("user", rr.Response.Payload),
		)
	default:
		w.WriteHeader(http.StatusNotImplemented)
		return nil
	}
	// User refreshed token successfully
	if err := p.authorizeLoginRequest(ctx, w, r, rr); err != nil {
		w.WriteHeader(rr.Response.Code)
		return nil
	}
	w.WriteHeader(rr.Response.Code)
	return nil
}
