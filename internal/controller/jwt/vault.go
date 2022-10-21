package jwt

import (
	"encoding/json"
	"strconv"

	"github.com/topfreegames/crossplane-provider-vault/apis/auth/v1alpha1"
	"k8s.io/utils/pointer"
)

type Role struct {
	Name                 string                 `json:"role_name"`
	Namespace            string                 `json:"namespace"`
	RoleType             string                 `json:"role_type"`
	BoundAudiences       []interface{}          `json:"bound_audiences"`
	UserClaim            string                 `json:"user_claim"`
	UserClaimJsonPointer bool                   `json:"user_claim_json_pointer"`
	BoundSubject         string                 `json:"bound_subject"`
	BoundClaims          map[string]interface{} `json:"bound_claims"`
	BoundClaimsType      string                 `json:"bound_claims_type"`
	ClaimMappings        map[string]interface{} `json:"claim_mappings"`
	OIDCScopes           []interface{}          `json:"oidc_scopes"`
	GroupsClaim          string                 `json:"groups_claim"`
	AllowedRedirectURIs  []interface{}          `json:"allowed_redirect_uris"`
	ClockSkewLeeway      json.Number            `json:"clock_skew_leeway"`
	ExpirationLeeway     json.Number            `json:"expiration_leeway"`
	NotBeforeLeeway      json.Number            `json:"not_before_leeway"`
	VerboseOIDCLogging   bool                   `json:"verbose_oidc_logging"`
	MaxAge               json.Number            `json:"max_age"`
	TokenTTL             json.Number            `json:"token_ttl"`
	TokenMaxTTL          json.Number            `json:"token_max_ttl"`
	TokenPolicies        []interface{}          `json:"token_policies"`
	TokenBoundCIDRS      []interface{}          `json:"token_bound_cidrs"`
	TokenExplicitMaxTTL  json.Number            `json:"token_explicit_max_ttl"`
	TokenNoDefaultPolicy bool                   `json:"token_no_default_policy"`
	TokenNumUses         json.Number            `json:"token_num_uses"`
	TokenPeriod          json.Number            `json:"token_period"`
	TokenType            string                 `json:"token_type"`
}

func RoleFromVault(data map[string]interface{}) *Role {
	role := Role{}
	jsonObj, _ := json.Marshal(data)
	json.Unmarshal(jsonObj, &role)
	return &role
}

func ternary[T any](exp bool, a T, b T) T {
	if exp {
		return a
	}

	return b
}

func RoleFromCrossplane(crossplane *v1alpha1.Jwt) *Role {
	d := crossplane.Spec.ForProvider
	r := &Role{
		Name:                 crossplane.Name,
		Namespace:            *ternary(d.Namespace == nil, pointer.String(""), d.Namespace),
		RoleType:             *ternary(d.Namespace == nil, pointer.String(""), d.RoleType),
		BoundAudiences:       sliceToInterface(d.BoundAudiences),
		UserClaim:            *ternary(d.Namespace == nil, pointer.String(""), d.UserClaim),
		UserClaimJsonPointer: *ternary(d.Namespace == nil, pointer.Bool(false), d.UserClaimJsonPointer),
		BoundSubject:         *ternary(d.Namespace == nil, pointer.String(""), d.BoundSubject),
		BoundClaims:          mapToInterface(d.BoundClaims),
		BoundClaimsType:      *ternary(d.Namespace == nil, pointer.String(""), d.BoundClaimsType),
		ClaimMappings:        mapToInterface(d.ClaimMappings),
		OIDCScopes:           sliceToInterface(d.OIDCScopes),
		GroupsClaim:          *ternary(d.Namespace == nil, pointer.String(""), d.GroupsClaim),
		AllowedRedirectURIs:  sliceToInterface(d.AllowedRedirectURIs),
		ClockSkewLeeway:      intToJSONNumber(d.ClockSkewLeeway),
		ExpirationLeeway:     intToJSONNumber(d.ExpirationLeeway),
		NotBeforeLeeway:      intToJSONNumber(d.NotBeforeLeeway),
		VerboseOIDCLogging:   *ternary(d.Namespace == nil, pointer.Bool(false), d.VerboseOIDCLogging),
		MaxAge:               intToJSONNumber(d.MaxAge),
		TokenTTL:             intToJSONNumber(d.TokenTTL),
		TokenMaxTTL:          intToJSONNumber(d.TokenMaxTTL),
		TokenPolicies:        sliceToInterface(d.TokenPolicies),
		TokenBoundCIDRS:      sliceToInterface(d.TokenBoundCIDRS),
		TokenExplicitMaxTTL:  intToJSONNumber(d.TokenExplicitMaxTTL),
		TokenNoDefaultPolicy: *ternary(d.Namespace == nil, pointer.Bool(false), d.TokenNoDefaultPolicy),
		TokenNumUses:         intToJSONNumber(d.TokenNumUses),
		TokenPeriod:          intToJSONNumber(d.TokenPeriod),
		TokenType:            *ternary(d.Namespace == nil, pointer.String(""), d.TokenType),
	}

	return r
}

func intToJSONNumber(n *int) json.Number {
	if n == nil {
		return json.Number("0")
	}

	num := *n
	number := json.Number(strconv.Itoa(num))
	return number
}

func sliceToInterface[T any](entry []T) []interface{} {
	r := make([]interface{}, len(entry))
	for i := range entry {
		r[i] = entry[i]
	}
	return r
}

func mapToInterface[T any](entry map[string]T) map[string]interface{} {
	r := make(map[string]interface{})
	for key, value := range entry {
		r[key] = value
	}
	return r
}
