// Copyright 2020 The gVisor Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package webhook provides GitHub webhook support.
//
// This webhook implements basic CI/CD functionality. It launches relevant
// builds on Google Cloud Builder, watches for results and extracts URLs.
package webhook

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"github.com/google/go-github/github"
	secretmanagerpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1"
)

var (
	githubWebhookSecret      = flag.String("github-webhook-secret", "github-webhook-secret", "The secret name for the webhook.")
	refreshPeriod            = flag.Duration("refresh-period", 10*time.Minute, "The refresh time for secrets.")
	presubmitServiceAccount  = flag.String("presubmit-service-account", "presubmit-service-account", "The secret name for the presubmit service account.")
	postsubmitServiceAccount = flag.String("postsubmit-service-account", "postsubmit-service-account", "The secret name for the postsubmit service account.")
)

// loadSecret loads a secret from the current project.
func loadSecret(secretName string) ([]byte, error) {
	ctx := context.Background()
	c, err := secretmanager.NewClient(ctx)
	if err != nil {
		return nil, err
	}

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: secretName,
	}
	resp, err := c.AccessSecretVersion(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.GetPayload().GetData(), nil
}

// periodicSecret is a function that will reload a value periodically.
func periodicSecret(secretName string, period time.Duration) func() ([]byte, error) {
	var (
		mu          sync.Mutex
		lastLoaded  time.Time
		cachedValue []byte
		cachedErr   error
	)
	return func() ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		if time.Since(lastLoaded) > period {
			cachedValue, cachedErr = loadSecret(secretName)
			lastLoaded = time.Now()
		}
		return cachedValue, cachedErr
	}
}

// handler is the webhook handler.
type handler struct {
	githubWebhookSecret      func() ([]byte, error)
	presubmitServiceAccount  func() ([]byte, error)
	postsubmitServiceAccount func() ([]byte, error)
}

// logError writes an error to the caller and logs.
func (h *handler) logError(w http.ResponseWriter, fmtStr string, v ...interface{}) {
	w.WriteHeader(500)
	fmt.Fprintf(w, fmtStr, v...)
	log.Printf(fmtStr, v...)
}

// handleEvent is the main entrypoint.
func (h *handler) handleEvent(w http.ResponseWriter, event interface{}) error {
	log.Printf("Received event: %+v\n", event)
	return nil
}

// Webhook returns the webhook entrypoint.
func Webhook() http.Handler {
	h := handler{
		githubWebhookSecret:      periodicSecret(*githubWebhookSecret, *refreshPeriod),
		presubmitServiceAccount:  periodicSecret(*presubmitServiceAccount, *refreshPeriod),
		postsubmitServiceAccount: periodicSecret(*postsubmitServiceAccount, *refreshPeriod),
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the cached secret.
		s, err := h.githubWebhookSecret()
		if err != nil {
			h.logError(w, "Error fetching GitHub webhook secret: %v\n", err)
			return
		}

		// Validate the payload signature.
		payload, err := github.ValidatePayload(r, s)
		if err != nil {
			h.logError(w, "Error validating payload: %v\n", err)
			return
		}

		// Parse the actual payload data.
		event, err := github.ParseWebHook(github.WebHookType(r), payload)
		if err != nil {
			h.logError(w, "Error parsing payload: %v\n", err)
			return
		}

		// Handle the event.
		if err := h.handleEvent(w, event); err != nil {
			h.logError(w, "Error handling event: %v\n", err)
			return
		}
	})
}
