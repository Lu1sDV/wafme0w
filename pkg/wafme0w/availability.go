package wafme0w

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// ChannelState describes how much faithful evidence a response channel supplies.
type ChannelState string

const (
	ChannelComplete    ChannelState = "complete"
	ChannelIncomplete  ChannelState = "incomplete"
	ChannelUnavailable ChannelState = "unavailable"
	ChannelUnknown     ChannelState = "unknown"
)

// EvidenceAvailability describes independent response channels. Every member
// must be populated. Status and reason accept complete or unavailable; headers
// additionally accept incomplete; body additionally accepts incomplete/unknown.
// A complete empty channel is observed, unlike an unavailable channel.
// Nil *EvidenceAvailability preserves legacy interpretation, not a completeness
// guarantee. Unknown body completeness does not mean known truncation.
type EvidenceAvailability struct {
	Status  ChannelState `json:"status"`
	Headers ChannelState `json:"headers"`
	Reason  ChannelState `json:"reason"`
	Body    ChannelState `json:"body"`
}

// Non-pointer JSON fields receive null too, so neither a repeated availability
// object nor a repeated channel can silently merge into earlier complete data.
type availabilityJSON struct {
	seen  bool
	value *EvidenceAvailability
}

func (a *availabilityJSON) UnmarshalJSON(data []byte) error {
	if a.seen {
		return fmt.Errorf("duplicate availability member")
	}
	a.seen = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		a.value = nil
		return nil
	}
	var channels struct {
		Status  availabilityChannelJSON `json:"status"`
		Headers availabilityChannelJSON `json:"headers"`
		Reason  availabilityChannelJSON `json:"reason"`
		Body    availabilityChannelJSON `json:"body"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&channels); err != nil {
		return err
	}
	a.value = &EvidenceAvailability{
		Status: channels.Status.value, Headers: channels.Headers.value,
		Reason: channels.Reason.value, Body: channels.Body.value,
	}
	return nil
}

type availabilityChannelJSON struct {
	seen  bool
	value ChannelState
}

func (c *availabilityChannelJSON) UnmarshalJSON(data []byte) error {
	if c.seen {
		return fmt.Errorf("duplicate availability channel")
	}
	c.seen = true
	return json.Unmarshal(data, &c.value)
}

func validateEvidenceAvailability(observation Evidence) error {
	a := observation.Availability
	if a == nil {
		return nil
	}
	if a.Status != ChannelComplete && a.Status != ChannelUnavailable {
		return fmt.Errorf("invalid status availability %q", a.Status)
	}
	if a.Reason != ChannelComplete && a.Reason != ChannelUnavailable {
		return fmt.Errorf("invalid reason availability %q", a.Reason)
	}
	if a.Headers != ChannelComplete && a.Headers != ChannelIncomplete && a.Headers != ChannelUnavailable {
		return fmt.Errorf("invalid headers availability %q", a.Headers)
	}
	if a.Body != ChannelComplete && a.Body != ChannelIncomplete && a.Body != ChannelUnavailable && a.Body != ChannelUnknown {
		return fmt.Errorf("invalid body availability %q", a.Body)
	}
	if a.Status == ChannelComplete && (observation.StatusCode < 100 || observation.StatusCode > 999) {
		return fmt.Errorf("complete status requires a three-digit HTTP status")
	}
	if a.Status == ChannelUnavailable && observation.StatusCode != 0 {
		return fmt.Errorf("unavailable status must not retain a status code")
	}
	if a.Reason == ChannelUnavailable && observation.Reason != "" {
		return fmt.Errorf("unavailable reason must not retain a reason phrase")
	}
	if a.Headers == ChannelUnavailable && len(observation.Headers) != 0 {
		return fmt.Errorf("unavailable headers must not retain header values")
	}
	if a.Body == ChannelUnavailable && len(observation.Body) != 0 {
		return fmt.Errorf("unavailable body must not retain body bytes")
	}
	if a.Body == ChannelComplete && (observation.BodyTruncated || observation.ErrorCode != "" || observation.TransportError != "") {
		return fmt.Errorf("complete body contradicts truncation or response error")
	}
	return nil
}

// Normalize once per classifier observation; the nil legacy path allocates
// nothing and retains its status-based metadata and error-based body gates.
type evidenceChannels struct {
	status          bool
	reason          bool
	headers         bool
	headersComplete bool
	body            bool
}

func availableEvidenceChannels(observation Evidence) evidenceChannels {
	if a := observation.Availability; a != nil {
		return evidenceChannels{
			status: a.Status == ChannelComplete, reason: a.Reason == ChannelComplete,
			headers: a.Headers != ChannelUnavailable, headersComplete: a.Headers == ChannelComplete,
			body: a.Body == ChannelComplete,
		}
	}
	metadata := observation.StatusCode >= 100 && observation.StatusCode <= 999
	return evidenceChannels{
		status: metadata, reason: metadata, headers: metadata, headersComplete: metadata,
		body: metadata && !observation.BodyTruncated && observation.TransportError == "" && observation.ErrorCode == "",
	}
}
