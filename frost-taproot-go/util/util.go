// Package util provides utility functions.
package util

import (
	"fmt"
)

// RecordNotFoundError indicates a record was not found.
type RecordNotFoundError struct {
	Idx uint32
}

func (e *RecordNotFoundError) Error() string {
	return fmt.Sprintf("record not found for index: %d", e.Idx)
}

// AssertionError indicates an assertion failed.
type AssertionError struct {
	Message string
}

func (e *AssertionError) Error() string {
	return fmt.Sprintf("assertion failed: %s", e.Message)
}

// InvalidPointError indicates invalid point encoding.
type InvalidPointError struct{}

func (e *InvalidPointError) Error() string {
	return "invalid point encoding"
}

// BothPointsNullError indicates both points are null.
type BothPointsNullError struct{}

func (e *BothPointsNullError) Error() string {
	return "both points are null"
}

// ScalarInversionError indicates scalar inversion failed.
type ScalarInversionError struct{}

func (e *ScalarInversionError) Error() string {
	return "scalar inversion failed (zero scalar)"
}

// HasID is implemented by types that carry a participant index.
type HasID interface {
	GetID() uint32
}

// GetRecord finds a record by ID in a slice of items that have an ID field.
func GetRecord[T HasID](records []T, idx uint32) (T, error) {
	var zero T
	for _, r := range records {
		if r.GetID() == idx {
			return r, nil
		}
	}
	return zero, &RecordNotFoundError{Idx: idx}
}

// OK asserts that value is true.
func OK(value bool, message string) error {
	if !value {
		return &AssertionError{Message: message}
	}
	return nil
}

// IsIncluded asserts that item is in array.
func IsIncluded[T comparable](array []T, item T) error {
	for _, v := range array {
		if v == item {
			return nil
		}
	}
	return &AssertionError{Message: "item is not included in array"}
}

// IsUniqueSet asserts that all items in array are unique.
func IsUniqueSet[T comparable](array []T) error {
	seen := make(map[T]int)
	for _, v := range array {
		seen[v]++
		if seen[v] > 1 {
			return &AssertionError{Message: fmt.Sprintf("item in set is not unique: %v", v)}
		}
	}
	return nil
}

// IsEqualSet asserts that all items in array are equal.
func IsEqualSet[T comparable](array []T) error {
	if len(array) <= 1 {
		return nil
	}
	first := array[0]
	for _, v := range array[1:] {
		if v != first {
			return &AssertionError{Message: "set does not have equal items"}
		}
	}
	return nil
}

// EqualArrSize asserts that two arrays have equal length.
func EqualArrSize[T, U any](a []T, b []U) error {
	if len(a) != len(b) {
		return &AssertionError{Message: fmt.Sprintf("array lengths are unequal: %d !== %d", len(a), len(b))}
	}
	return nil
}

// HexToBytes decodes a hex string to bytes.
func HexToBytes(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("invalid hex string length")
	}
	result := make([]byte, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		b, err := parseHexByte(s[i : i+2])
		if err != nil {
			return nil, err
		}
		result[i/2] = b
	}
	return result, nil
}

// HexTo32 decodes a hex string to [32]byte.
func HexTo32(s string) ([32]byte, error) {
	b, err := HexToBytes(s)
	if err != nil {
		return [32]byte{}, err
	}
	if len(b) != 32 {
		return [32]byte{}, fmt.Errorf("expected 32 bytes, got %d", len(b))
	}
	var out [32]byte
	copy(out[:], b)
	return out, nil
}

// HexTo33 decodes a hex string to [33]byte.
func HexTo33(s string) ([33]byte, error) {
	b, err := HexToBytes(s)
	if err != nil {
		return [33]byte{}, err
	}
	if len(b) != 33 {
		return [33]byte{}, fmt.Errorf("expected 33 bytes, got %d", len(b))
	}
	var out [33]byte
	copy(out[:], b)
	return out, nil
}

func parseHexByte(s string) (byte, error) {
	if len(s) != 2 {
		return 0, fmt.Errorf("invalid hex byte")
	}
	hi := hexValue(s[0])
	lo := hexValue(s[1])
	if hi < 0 || lo < 0 {
		return 0, fmt.Errorf("invalid hex character")
	}
	return byte(hi<<4 | lo), nil
}

func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	}
	return -1
}

// BytesToHex encodes bytes to a hex string.
func BytesToHex(b []byte) string {
	const hexChars = "0123456789abcdef"
	result := make([]byte, len(b)*2)
	for i, v := range b {
		result[i*2] = hexChars[v>>4]
		result[i*2+1] = hexChars[v&0x0f]
	}
	return string(result)
}
