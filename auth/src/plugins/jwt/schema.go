package jwt

import "github.com/brick-org/brick/auth/src/types"

// Schema describes the persisted JWKS keys.
// Upstream vendor/better-auth/packages/better-auth/src/plugins/jwt/schema.ts:3-40.
func Schema() types.PluginSchema {
	return types.PluginSchema{
		"jwks": {
			Fields: map[string]types.FieldAttribute{
				"publicKey":  {Type: types.FieldTypeString, Required: jwtBool(true)},
				"privateKey": {Type: types.FieldTypeString, Required: jwtBool(true), Returned: jwtBool(false)},
				"createdAt":  {Type: types.FieldTypeDate, Required: jwtBool(true)},
				"expiresAt":  {Type: types.FieldTypeDate, Required: jwtBool(false)},
				"alg":        {Type: types.FieldTypeString, Required: jwtBool(false)},
				"crv":        {Type: types.FieldTypeString, Required: jwtBool(false)},
			},
		},
	}
}

func jwtBool(value bool) *bool { return &value }
