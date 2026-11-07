package wireguard

import (
	"encoding/base64"
	"errors"
	"strings"
	"unicode"
)

// JoinCodePrefix marks a join code: the client file of a site as one line,
// so it can be copied between two browsers or terminals without a file.
// The code is the file itself (base64url), not a reference to it: it holds
// the private key of the site and must be treated like the file.
const JoinCodePrefix = "godeb-join:"

// maxJoinConfig bounds a decoded join code; a client file is well below 2 KB.
const maxJoinConfig = 16 << 10

// JoinCode encodes a client configuration as a join code.
func JoinCode(conf string) string {
	return JoinCodePrefix + base64.RawURLEncoding.EncodeToString([]byte(conf))
}

// decodeJoinInput returns the client configuration for content, which is
// either the file itself or a join code. Whitespace inside a code is
// ignored, because terminals and mail clients wrap long lines.
func decodeJoinInput(content string) (string, error) {
	trimmed := strings.TrimSpace(content)
	rest, ok := cutPrefixFold(trimmed, JoinCodePrefix)
	if !ok {
		return content, nil
	}
	rest = strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, rest)
	// Accept padded and standard base64 too, in case a tool re-encoded it.
	rest = strings.TrimRight(rest, "=")
	rest = strings.NewReplacer("+", "-", "/", "_").Replace(rest)
	if base64.RawURLEncoding.DecodedLen(len(rest)) > maxJoinConfig {
		return "", errors.New("Beitrittscode ist zu lang")
	}
	data, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		return "", errors.New("Beitrittscode ist unvollständig oder beschädigt; bitte vollständig kopieren")
	}
	return string(data), nil
}

func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || !strings.EqualFold(s[:len(prefix)], prefix) {
		return s, false
	}
	return s[len(prefix):], true
}

// CompleteJoinCode reports whether s is a join code that decodes into a
// valid client file, so `godeb-play setup --join -` can stop reading after the
// code even when it was pasted across several lines.
func CompleteJoinCode(s string) bool {
	if _, ok := cutPrefixFold(strings.TrimSpace(s), JoinCodePrefix); !ok {
		return false
	}
	conf, err := decodeJoinInput(s)
	if err != nil {
		return false
	}
	_, _, err = parseJoinConfig(conf)
	return err == nil
}
