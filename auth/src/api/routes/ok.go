package routes

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

type okOutput struct {
	Body struct {
		OK bool `json:"ok"`
	}
}

// Ok registers GET /ok (upstream `ok`).
func Ok(api huma.API, basePath string) {
	huma.Register(api, huma.Operation{
		Tags:        []string{"Auth"},
		Method:      http.MethodGet,
		Path:        basePath + "/ok",
		OperationID: "auth-ok",
		Summary:     "Check if the auth API is working",
	}, func(_ context.Context, _ *struct{}) (*okOutput, error) {
		out := &okOutput{}
		out.Body.OK = true
		return out, nil
	})
}
