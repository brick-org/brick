package jwt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	jose "github.com/go-jose/go-jose/v4"
)

var errJWTVerification = errors.New("jwt: verification failed")

// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/verify.ts:13-69.
func verifyJWT(token string, keys []JWK, options VerifyOptions) (JWTClaims, error) {
	return verifyJWTProfile(token, keys, options, false)
}

// verifyAccessToken accepts only RFC 9068-style OAuth access-token JWTs.
func verifyAccessToken(token string, keys []JWK, options VerifyOptions) (JWTClaims, error) {
	return verifyJWTProfile(token, keys, options, true)
}

func verifyJWTProfile(token string, keys []JWK, options VerifyOptions, accessToken bool) (JWTClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return JWTClaims{}, fmt.Errorf("%w: malformed compact JWS", errJWTVerification)
	}
	headerBytes, err := base64.RawURLEncoding.Strict().DecodeString(parts[0])
	if err != nil {
		return JWTClaims{}, fmt.Errorf("%w: malformed protected header", errJWTVerification)
	}
	header, err := decodeJSONObject(headerBytes)
	if err != nil {
		return JWTClaims{}, fmt.Errorf("%w: malformed protected header: %v", errJWTVerification, err)
	}
	kid, ok := header["kid"].(string)
	if !ok || kid == "" {
		return JWTClaims{}, fmt.Errorf("%w: missing kid", errJWTVerification)
	}
	algName, ok := header["alg"].(string)
	if !ok || algName == "" {
		return JWTClaims{}, fmt.Errorf("%w: missing algorithm", errJWTVerification)
	}
	if accessToken {
		typ, ok := header["typ"].(string)
		if !ok || typ != "at+jwt" {
			return JWTClaims{}, fmt.Errorf("%w: invalid access-token type", errJWTVerification)
		}
	}

	allowedAlgorithms := allowedJOSEAlgorithms(options.AllowedAlgorithms)
	if !slices.Contains(allowedAlgorithms, jose.SignatureAlgorithm(algName)) {
		return JWTClaims{}, fmt.Errorf("%w: disallowed algorithm %q", errJWTVerification, algName)
	}
	parsed, err := jose.ParseSignedCompact(token, allowedAlgorithms)
	if err != nil || len(parsed.Signatures) != 1 {
		return JWTClaims{}, fmt.Errorf("%w: malformed or unsupported JWS", errJWTVerification)
	}
	protected := parsed.Signatures[0].Protected
	if protected.KeyID != kid || protected.Algorithm != algName {
		return JWTClaims{}, fmt.Errorf("%w: inconsistent protected header", errJWTVerification)
	}

	var key *JWK
	for i := range keys {
		if keys[i].ID != kid {
			continue
		}
		if key != nil {
			return JWTClaims{}, fmt.Errorf("%w: ambiguous key id %q", errJWTVerification, kid)
		}
		key = &keys[i]
	}
	if key == nil {
		return JWTClaims{}, fmt.Errorf("%w: no key for kid %q", errJWTVerification, kid)
	}

	keyAlgorithm := AlgEdDSA
	if key.Alg != nil {
		keyAlgorithm = *key.Alg
	}
	if string(keyAlgorithm) != algName || !slices.Contains(optionsAllowedAlgorithms(options.AllowedAlgorithms), keyAlgorithm) {
		return JWTClaims{}, fmt.Errorf("%w: algorithm does not match key", errJWTVerification)
	}
	if _, err := decodeJSONObject([]byte(key.PublicKeyJSON)); err != nil {
		return JWTClaims{}, fmt.Errorf("%w: malformed public key", errJWTVerification)
	}
	var publicKey jose.JSONWebKey
	if err := json.Unmarshal([]byte(key.PublicKeyJSON), &publicKey); err != nil {
		return JWTClaims{}, fmt.Errorf("%w: malformed public key", errJWTVerification)
	}
	if !publicKey.IsPublic() || !publicKey.Valid() || (publicKey.Use != "" && publicKey.Use != "sig") ||
		(publicKey.KeyID != "" && publicKey.KeyID != key.ID) ||
		(publicKey.Algorithm != "" && publicKey.Algorithm != algName) ||
		!keyMatchesAlgorithm(publicKey.Key, keyAlgorithm) {
		return JWTClaims{}, fmt.Errorf("%w: invalid public key for algorithm %q", errJWTVerification, algName)
	}

	payload, err := parsed.Verify(publicKey.Key)
	if err != nil {
		return JWTClaims{}, fmt.Errorf("%w: invalid signature", errJWTVerification)
	}
	claimValues, err := decodeJSONObject(payload)
	if err != nil {
		return JWTClaims{}, fmt.Errorf("%w: malformed claims: %v", errJWTVerification, err)
	}
	claims, err := parseJWTClaims(claimValues)
	if err != nil {
		return JWTClaims{}, fmt.Errorf("%w: %v", errJWTVerification, err)
	}
	if err := validateJWTClaims(claims, claimValues, options, accessToken); err != nil {
		return JWTClaims{}, err
	}
	return claims, nil
}

func allowedJOSEAlgorithms(configured []JWSAlgorithm) []jose.SignatureAlgorithm {
	allowed := optionsAllowedAlgorithms(configured)
	out := make([]jose.SignatureAlgorithm, 0, len(allowed))
	for _, algorithm := range allowed {
		out = append(out, jose.SignatureAlgorithm(algorithm))
	}
	return out
}

func optionsAllowedAlgorithms(configured []JWSAlgorithm) []JWSAlgorithm {
	supported := SupportedAlgorithms()
	if len(configured) == 0 {
		return supported
	}
	allowed := make([]JWSAlgorithm, 0, len(configured))
	for _, algorithm := range configured {
		if slices.Contains(supported, algorithm) && !slices.Contains(allowed, algorithm) {
			allowed = append(allowed, algorithm)
		}
	}
	return allowed
}

func keyMatchesAlgorithm(key any, algorithm JWSAlgorithm) bool {
	switch algorithm {
	case AlgEdDSA:
		_, ok := key.(ed25519.PublicKey)
		return ok
	case AlgES256:
		publicKey, ok := key.(*ecdsa.PublicKey)
		return ok && publicKey.Curve == elliptic.P256()
	case AlgES512:
		publicKey, ok := key.(*ecdsa.PublicKey)
		return ok && publicKey.Curve == elliptic.P521()
	case AlgPS256, AlgRS256:
		publicKey, ok := key.(*rsa.PublicKey)
		return ok && publicKey.N != nil && publicKey.N.BitLen() >= 2048
	default:
		return false
	}
}

func parseJWTClaims(values map[string]any) (JWTClaims, error) {
	var claims JWTClaims
	var err error
	if claims.Issuer, err = stringClaim(values, "iss"); err != nil {
		return JWTClaims{}, err
	}
	if claims.Subject, err = stringClaim(values, "sub"); err != nil {
		return JWTClaims{}, err
	}
	if claims.JWTID, err = stringClaim(values, "jti"); err != nil {
		return JWTClaims{}, err
	}
	if value, ok := values["aud"]; ok {
		claims.Audience, err = audienceClaim(value)
		if err != nil {
			return JWTClaims{}, err
		}
	}
	if claims.ExpiresAt, err = numericDateClaim(values, "exp"); err != nil {
		return JWTClaims{}, err
	}
	if claims.NotBefore, err = numericDateClaim(values, "nbf"); err != nil {
		return JWTClaims{}, err
	}
	if claims.IssuedAt, err = numericDateClaim(values, "iat"); err != nil {
		return JWTClaims{}, err
	}
	claims.CustomClaims = make(Payload)
	for name, value := range values {
		switch name {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
		default:
			claims.CustomClaims[name] = value
		}
	}
	return claims, nil
}

func stringClaim(values map[string]any, name string) (string, error) {
	value, ok := values[name]
	if !ok {
		return "", nil
	}
	claim, ok := value.(string)
	if !ok {
		return "", fmt.Errorf("claim %q must be a string", name)
	}
	return claim, nil
}

func audienceClaim(value any) ([]string, error) {
	var audience []string
	switch claim := value.(type) {
	case string:
		audience = []string{claim}
	case []any:
		audience = make([]string, len(claim))
		for i, item := range claim {
			value, ok := item.(string)
			if !ok {
				return nil, errors.New(`claim "aud" must be a string or array of strings`)
			}
			audience[i] = value
		}
	default:
		return nil, errors.New(`claim "aud" must be a string or array of strings`)
	}
	if len(audience) == 0 {
		return nil, errors.New(`claim "aud" must not be empty`)
	}
	for i, value := range audience {
		if value == "" || slices.Contains(audience[:i], value) {
			return nil, errors.New(`claim "aud" contains an empty or duplicate value`)
		}
	}
	return audience, nil
}

func numericDateClaim(values map[string]any, name string) (*int64, error) {
	value, ok := values[name]
	if !ok {
		return nil, nil
	}
	number, ok := value.(json.Number)
	if !ok {
		return nil, fmt.Errorf("claim %q must be a number", name)
	}
	seconds, err := strconv.ParseFloat(string(number), 64)
	if err != nil || math.IsInf(seconds, 0) || math.IsNaN(seconds) ||
		seconds < float64(math.MinInt64) || seconds >= -float64(math.MinInt64) {
		return nil, fmt.Errorf("claim %q is outside the supported NumericDate range", name)
	}
	date := int64(seconds)
	return &date, nil
}

func validateJWTClaims(claims JWTClaims, values map[string]any, options VerifyOptions, accessToken bool) error {
	if claims.Subject == "" || len(claims.Audience) == 0 {
		return fmt.Errorf("%w: subject and audience are required", errJWTVerification)
	}
	if accessToken && (claims.Issuer == "" || claims.ExpiresAt == nil || claims.IssuedAt == nil || claims.JWTID == "") {
		return fmt.Errorf("%w: access token requires issuer, expiration, issued-at, and JWT ID", errJWTVerification)
	}
	if options.RequireExpiration && claims.ExpiresAt == nil {
		return fmt.Errorf("%w: expiration is required", errJWTVerification)
	}
	if options.Issuer != "" && claims.Issuer != options.Issuer {
		return fmt.Errorf("%w: issuer mismatch", errJWTVerification)
	}
	if len(options.Audience) != 0 && !audienceMatches(claims.Audience, options.Audience) {
		return fmt.Errorf("%w: audience mismatch", errJWTVerification)
	}
	if accessToken {
		clientID, ok := values["client_id"].(string)
		scope, scopeOK := values["scope"].(string)
		if !ok || clientID == "" || !scopeOK || !validOAuthScope(scope) {
			return fmt.Errorf("%w: access token requires client_id and scope", errJWTVerification)
		}
	}

	now := time.Now()
	leeway := options.Leeway
	if leeway < 0 {
		leeway = 0
	}
	if claims.ExpiresAt != nil && !now.Before(time.Unix(*claims.ExpiresAt, 0).Add(leeway)) {
		return fmt.Errorf("%w: token expired", errJWTVerification)
	}
	if claims.NotBefore != nil && now.Add(leeway).Before(time.Unix(*claims.NotBefore, 0)) {
		return fmt.Errorf("%w: token not yet valid", errJWTVerification)
	}
	if accessToken && claims.IssuedAt != nil && time.Unix(*claims.IssuedAt, 0).After(now.Add(leeway)) {
		return fmt.Errorf("%w: access token issued-at is in the future", errJWTVerification)
	}
	return nil
}

func audienceMatches(claimed, expected []string) bool {
	for _, audience := range expected {
		if slices.Contains(claimed, audience) {
			return true
		}
	}
	return false
}

func validOAuthScope(scope string) bool {
	if scope == "" {
		return false
	}
	for _, token := range strings.Split(scope, " ") {
		if token == "" {
			return false
		}
		for i := 0; i < len(token); i++ {
			char := token[i]
			if char != '!' && (char < '#' || char > '[') && (char < ']' || char > '~') {
				return false
			}
		}
	}
	return true
}

func decodeJSONObject(data []byte) (map[string]any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("JSON is not valid UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := decodeJSONValue(decoder)
	if err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return nil, errors.New("multiple JSON values")
		}
		return nil, err
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("JSON value must be an object")
	}
	return object, nil
}

func decodeJSONValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return token, nil
	}
	switch delimiter {
	case '{':
		object := make(map[string]any)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object key must be a string")
			}
			if _, duplicate := object[key]; duplicate {
				return nil, fmt.Errorf("duplicate object key %q", key)
			}
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			object[key] = value
		}
		end, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim('}') {
			return nil, errors.New("object is not properly closed")
		}
		return object, nil
	case '[':
		var array []any
		for decoder.More() {
			value, err := decodeJSONValue(decoder)
			if err != nil {
				return nil, err
			}
			array = append(array, value)
		}
		end, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		if end != json.Delim(']') {
			return nil, errors.New("array is not properly closed")
		}
		return array, nil
	default:
		return nil, errors.New("unexpected JSON delimiter")
	}
}
