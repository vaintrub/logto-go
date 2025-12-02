// Package models contains data types for the Logto client.
package models

import "time"

// User represents user data from Logto.
type User struct {
	ID          string
	Name        string
	Email       string // primary_email
	Avatar      string
	IsSuspended bool
	CustomData  map[string]interface{}
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// UserUpdate represents fields that can be updated for a user.
type UserUpdate struct {
	Name   *string
	Avatar *string
}
