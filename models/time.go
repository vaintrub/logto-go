package models

import (
	"encoding/json"
	"time"
)

// UnixMilliTime is a time.Time wrapper that marshals/unmarshals as Unix milliseconds.
// Logto API returns timestamps as int64 Unix milliseconds.
type UnixMilliTime struct {
	time.Time
}

// UnmarshalJSON implements json.Unmarshaler for UnixMilliTime.
// It handles both int64 (Unix milliseconds) and string (RFC3339) formats.
func (t *UnixMilliTime) UnmarshalJSON(data []byte) error {
	// Try to unmarshal as int64 first (Unix milliseconds)
	var millis int64
	if err := json.Unmarshal(data, &millis); err == nil {
		t.Time = time.UnixMilli(millis)
		return nil
	}

	// Fall back to standard time.Time unmarshalling (RFC3339 string)
	return json.Unmarshal(data, &t.Time)
}

// MarshalJSON implements json.Marshaler for UnixMilliTime.
// It marshals as Unix milliseconds to match Logto API format.
func (t UnixMilliTime) MarshalJSON() ([]byte, error) {
	return json.Marshal(t.UnixMilli())
}
