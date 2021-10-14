// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package google

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/apigee/apigee-remote-service-golib/v2/log"
	"golang.org/x/oauth2"
	iam "google.golang.org/api/iamcredentials/v1"
	"google.golang.org/api/option"
)

const (
	defaultRefreshInterval = 30 * time.Minute

	serviceAccountNameFormat = "projects/-/serviceAccounts/%s"
)

// IAMService defines the IAM service for a particular service account.
type IAMService struct {
	ctx        context.Context
	cancelFunc context.CancelFunc
	svc        *iam.Service
	saName     string
}

// AccessTokenSource defines an access token source.
// It supplies access tokens via Token() method.
type AccessTokenSource struct {
	iamsvc *iam.Service
	saName string
	scopes []string

	token *oauth2.Token
	mu    sync.Mutex
}

// IdentityTokenSource defines an ID token source.
// It supplies ID tokens via Token() method.
type IdentityTokenSource struct {
	iamsvc       *iam.Service
	saName       string
	audience     string
	includeEmail bool

	token *oauth2.Token
	mu    sync.Mutex
}

// NewIAMService creates a new IAM service with given list of client options.
func NewIAMService(opts ...option.ClientOption) (*IAMService, error) {
	ctxWithCancel, cancelFunc := context.WithCancel(context.Background())
	iamsvc, err := iam.NewService(ctxWithCancel, opts...)
	if err != nil {
		cancelFunc()
		return nil, fmt.Errorf("failed to create new IAM credentials service: %v", err)
	}
	return &IAMService{
		ctx:        ctxWithCancel,
		cancelFunc: cancelFunc,
		svc:        iamsvc,
	}, nil
}

func (s *IAMService) Close() {
	s.cancelFunc()
}

// AccessTokenSource returns a new access token source. Service account email and scopes are required.
func (s *IAMService) AccessTokenSource(saEmail string, scopes []string, refreshInterval time.Duration) (*AccessTokenSource, error) {
	if saEmail == "" {
		return nil, fmt.Errorf("service account is required to create access token source")
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("scopes are required to create access token source")
	}
	ats := &AccessTokenSource{
		iamsvc: s.svc,
		saName: fmt.Sprintf(serviceAccountNameFormat, saEmail),
		scopes: scopes,
	}

	if refreshInterval == 0 {
		refreshInterval = defaultRefreshInterval
	}
	go func() {
		tick := time.NewTicker(refreshInterval)
		for {
			select {
			case <-tick.C:
				if err := ats.refresh(); err != nil {
					log.Errorf("%v", err)
				}
			case <-s.ctx.Done():
				tick.Stop()
				return
			}
		}
	}()

	if err := ats.refresh(); err != nil {
		log.Errorf("%v", err)
	}
	return ats, nil
}

// IdentityTokenSource returns a new ID token source. Service account email and audience are required.
func (s *IAMService) IdentityTokenSource(saEmail, audience string, includeEmail bool, refreshInterval time.Duration) (*IdentityTokenSource, error) {
	if saEmail == "" {
		return nil, fmt.Errorf("service account is required to create id token source")
	}
	if audience == "" {
		return nil, fmt.Errorf("audience is required to create id token source")
	}
	its := &IdentityTokenSource{
		iamsvc:       s.svc,
		saName:       s.saName,
		audience:     audience,
		includeEmail: includeEmail,
	}

	if refreshInterval == 0 {
		refreshInterval = defaultRefreshInterval
	}
	go func() {
		tick := time.NewTicker(refreshInterval)
		for {
			select {
			case <-tick.C:
				if err := its.refresh(); err != nil {
					log.Errorf("%v", err)
				}
			case <-s.ctx.Done():
				tick.Stop()
				return
			}
		}
	}()

	if err := its.refresh(); err != nil {
		log.Errorf("%v", err)
	}
	return its, nil
}

// Token returns the access token from the source.
func (ats *AccessTokenSource) Token() (*oauth2.Token, error) {
	if !ats.token.Valid() {
		if err := ats.refresh(); err != nil {
			return nil, err
		}
	}
	ats.mu.Lock()
	defer ats.mu.Unlock()
	// Deep copy the object to avoid data race.
	return &oauth2.Token{
		AccessToken: ats.token.AccessToken,
		Expiry:      ats.token.Expiry,
	}, nil
}

func (ats *AccessTokenSource) refresh() error {
	req := &iam.GenerateAccessTokenRequest{
		Scope: ats.scopes,
	}
	resp, err := ats.iamsvc.Projects.ServiceAccounts.GenerateAccessToken(ats.saName, req).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch access token for %q: %v", ats.saName, err)
	}
	t, err := time.Parse(time.RFC3339, resp.ExpireTime)
	if err != nil {
		return fmt.Errorf("failed to parse access token expire time for %q: %v", ats.saName, err)
	}
	ats.mu.Lock()
	defer ats.mu.Unlock()
	ats.token = &oauth2.Token{
		AccessToken: resp.AccessToken,
		Expiry:      t,
	}
	return nil
}

// Token returns the ID token from the source.
func (its *IdentityTokenSource) Token() (*oauth2.Token, error) {
	if !its.token.Valid() {
		if err := its.refresh(); err != nil {
			return nil, err
		}
	}
	its.mu.Lock()
	defer its.mu.Unlock()
	// Deep copy the object to avoid data race.
	return &oauth2.Token{
		AccessToken: its.token.AccessToken,
		Expiry:      its.token.Expiry,
	}, nil
}

func (its *IdentityTokenSource) refresh() error {
	req := &iam.GenerateIdTokenRequest{
		Audience:     its.audience,
		IncludeEmail: its.includeEmail,
	}
	resp, err := its.iamsvc.Projects.ServiceAccounts.GenerateIdToken(its.saName, req).Do()
	if err != nil {
		return fmt.Errorf("failed to fetch ID token for %q: %v", its.saName, err)
	}
	its.mu.Lock()
	defer its.mu.Unlock()
	its.token = &oauth2.Token{
		AccessToken: resp.Token,
		// ID token expires in one hour by default. Add 5 mins skew.
		Expiry: time.Now().Add(55 * time.Minute),
	}
	return nil
}
