package api

import (
	"errors"

	"github.com/go-acme/lego/v4/acme"
)

type ChallengeService service

// New Creates a challenge.
func (c *ChallengeService) New(chlgURL string) (acme.ExtendedChallenge, error) {
	if chlgURL == "" {
		return acme.ExtendedChallenge{}, errors.New("challenge[new]: empty URL")
	}

	// Challenge initiation is done by sending a JWS payload containing the trivial JSON object `{}`.
	// We use an empty struct instance as the postJSON payload here to achieve this result.
	var chlng acme.ExtendedChallenge
	resp, err := c.core.post(chlgURL, struct{}{}, &chlng)
	if err != nil {
		return acme.ExtendedChallenge{}, err
	}

	chlng.AuthorizationURL = getLink(resp.Header, "up")
	chlng.RetryAfter = getRetryAfter(resp)
	return chlng, nil
}

// Get Gets a challenge.
func (c *ChallengeService) Get(chlgURL string) (acme.ExtendedChallenge, error) {
	if chlgURL == "" {
		return acme.ExtendedChallenge{}, errors.New("challenge[get]: empty URL")
	}

	var chlng acme.ExtendedChallenge
	resp, err := c.core.postAsGet(chlgURL, &chlng)
	if err != nil {
		return acme.ExtendedChallenge{}, err
	}

	chlng.AuthorizationURL = getLink(resp.Header, "up")
	chlng.RetryAfter = getRetryAfter(resp)
	return chlng, nil
}

type ATCPayload struct {
	ATC string `json:"atc"`
}

func (c *ChallengeService) NewTkauth(chlgURL string, spcToken string) (acme.ExtendedChallenge, error) {
	if chlgURL == "" {
		return acme.ExtendedChallenge{}, errors.New("challenge[new]: empty URL")
	}

	// Challenge initiation is done by sending a JWS payload containing the trivial JSON object `{}`.
	// We use an empty struct instance as the postJSON payload here to achieve this result.
	var chlng acme.ExtendedChallenge
	atcPayload := ATCPayload{ATC: spcToken}
	resp, err := c.core.post(chlgURL, atcPayload, &chlng)
	if err != nil {
		return acme.ExtendedChallenge{}, err
	}

	chlng.AuthorizationURL = getLink(resp.Header, "up")
	chlng.RetryAfter = getRetryAfter(resp)
	return chlng, nil
}
