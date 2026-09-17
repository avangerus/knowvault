// Package ids mints typed-prefix canonical ULIDs of the exact shape the Stage 2
// schema accepts (`^[a-z]{2,16}_[0-7][0-9A-HJKMNP-TV-Z]{25}$`): a lowercase
// prefix, an underscore and a 26-character Crockford base32 ULID. Every catalog,
// version, extraction, evidence and sync-run identifier is server-generated
// here; a source-native id or human-readable string is never used as an id.
package ids

import (
	"crypto/rand"
	"errors"
	"regexp"
	"time"
)

// crockford is Crockford base32 without I, L, O and U, matching the schema
// character class. ULID encodes 128 bits as 26 characters.
const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

var prefixPattern = regexp.MustCompile(`^[a-z]{2,16}$`)

// ErrPrefix is returned when the requested prefix is not 2..16 lowercase ASCII
// letters.
var ErrPrefix = errors.New("ids: prefix must be 2..16 lowercase letters")

// New returns a fresh typed-prefix ULID such as "object_01J...". The timestamp
// is the current wall clock; randomness is read from the operating-system
// CSPRNG. It fails closed only if the prefix is invalid or the CSPRNG is
// unavailable.
func New(prefix string) (string, error) {
	return newAt(prefix, time.Now())
}

func newAt(prefix string, now time.Time) (string, error) {
	if !prefixPattern.MatchString(prefix) {
		return "", ErrPrefix
	}
	var raw [16]byte
	ms := uint64(now.UnixMilli())
	// 48-bit millisecond timestamp, big-endian, in the first six bytes.
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	if _, err := rand.Read(raw[6:]); err != nil {
		return "", err
	}
	return prefix + "_" + encode(raw), nil
}

// encode renders 128 bits as 26 Crockford base32 characters. The first
// character carries only the top two bits of the timestamp, so it is always in
// [0-7], exactly as the schema requires.
func encode(raw [16]byte) string {
	out := make([]byte, 26)
	out[0] = crockford[(raw[0]&0xE0)>>5]
	out[1] = crockford[raw[0]&0x1F]
	out[2] = crockford[(raw[1]&0xF8)>>3]
	out[3] = crockford[((raw[1]&0x07)<<2)|((raw[2]&0xC0)>>6)]
	out[4] = crockford[(raw[2]&0x3E)>>1]
	out[5] = crockford[((raw[2]&0x01)<<4)|((raw[3]&0xF0)>>4)]
	out[6] = crockford[((raw[3]&0x0F)<<1)|((raw[4]&0x80)>>7)]
	out[7] = crockford[(raw[4]&0x7C)>>2]
	out[8] = crockford[((raw[4]&0x03)<<3)|((raw[5]&0xE0)>>5)]
	out[9] = crockford[raw[5]&0x1F]
	out[10] = crockford[(raw[6]&0xF8)>>3]
	out[11] = crockford[((raw[6]&0x07)<<2)|((raw[7]&0xC0)>>6)]
	out[12] = crockford[(raw[7]&0x3E)>>1]
	out[13] = crockford[((raw[7]&0x01)<<4)|((raw[8]&0xF0)>>4)]
	out[14] = crockford[((raw[8]&0x0F)<<1)|((raw[9]&0x80)>>7)]
	out[15] = crockford[(raw[9]&0x7C)>>2]
	out[16] = crockford[((raw[9]&0x03)<<3)|((raw[10]&0xE0)>>5)]
	out[17] = crockford[raw[10]&0x1F]
	out[18] = crockford[(raw[11]&0xF8)>>3]
	out[19] = crockford[((raw[11]&0x07)<<2)|((raw[12]&0xC0)>>6)]
	out[20] = crockford[(raw[12]&0x3E)>>1]
	out[21] = crockford[((raw[12]&0x01)<<4)|((raw[13]&0xF0)>>4)]
	out[22] = crockford[((raw[13]&0x0F)<<1)|((raw[14]&0x80)>>7)]
	out[23] = crockford[(raw[14]&0x7C)>>2]
	out[24] = crockford[((raw[14]&0x03)<<3)|((raw[15]&0xE0)>>5)]
	out[25] = crockford[raw[15]&0x1F]
	return string(out)
}
