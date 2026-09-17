package brick

// ListResponse is the standard paginated list response shape.
// All list endpoints in Brick return this type.
type ListResponse[T any] struct {
	Data  []T   `json:"data"`
	Total int64 `json:"total"`
	Page  int   `json:"page"`
	Limit int   `json:"limit"`
}
