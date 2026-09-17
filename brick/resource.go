package brick

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/brick-org/brick/brick/db"
	"github.com/brick-org/brick/dsl/schema"
	"github.com/danielgtaylor/huma/v2"
	"github.com/uptrace/bun/driver/pgdriver"
)

// --- Generic I/O wrappers for Huma handlers ---
// Huma unwraps the Body field during serialization, so the OpenAPI schema
// reflects the inner type directly. Shapes are frozen by the OpenAPI
// snapshot (gen/openapi.json) — do not rename fields.

type GetInput struct {
	ID string `path:"id"`
	// Expand is accepted for OpenAPI stability. Children embedding was cut
	// (no DSL consumer); the parameter is ignored.
	Expand string `query:"expand"`
}

type CreateInput[B any] struct {
	Body B
}

type UpdateInput[B any] struct {
	ID   string `path:"id"`
	Body B
}

type DeleteInput struct {
	ID string `path:"id"`
}

type GetOutput[R any] struct {
	Body R
}

type ListOutput[R any] struct {
	Body ListResponse[R]
}

type CreateOutput[R any] struct {
	Body R
}

type UpdateOutput[R any] struct {
	Body R
}

// ListInputer is implemented by generated *ListInput types so the generic
// list handler can call ToListOptions() to build filter/pagination options.
type ListInputer interface {
	ToListOptions() db.ListOptions
}

// Schema carries a resource's type parameters and configuration.
// Generated code creates a type alias like:
//
//	type DealSchema = brick.Schema[DealRow, DealResponse, DealCreateBody, DealUpdateBody, DealListInput]
type Schema[Row, Response, CreateBody, UpdateBody, ListInput any] struct {
	Fields     schema.Fields
	Operations schema.Operations
	// PK declares the primary key column + autoname strategy. Nil keeps the
	// legacy default: a UUID "id" column.
	PK *schema.PK
	// Guards applies to ALL CRUD operations uniformly. Per-op guards live on Access.
	// Both run; uniform Guards first, then the matching Access slot.
	Guards []Guard[map[string]any]
	Access Access
	Hooks  Hooks[map[string]any, map[string]any]
	// LookupField overrides the PK column for Get/Update/Delete addressing
	// (LookupField || PK.Column || "id"). Kept for Frappe tables addressed
	// by `name`.
	LookupField string
	// AutoCreate is retained for struct shape compatibility but IGNORED by
	// the exec pipeline (cut with children/singleton — no DSL user).
	AutoCreate bool
}

// ResourceConfig is a resource descriptor created via the generic
// Resource() function. Pass to Brick.Register.
type ResourceConfig struct {
	Name        string
	Table       string
	Model       any
	Schema      *schema.DynamicSchema
	Operations  schema.Operations
	Guards      []Guard[map[string]any]
	Access      Access
	Hooks       Hooks[map[string]any, map[string]any]
	LookupField string
	AutoCreate  bool // ignored by exec (see Schema.AutoCreate)
	// registerRoutesFn is set by Resource() and runs the typed CRUD
	// registration. Unexported: app code cannot override routes (the only
	// custom-route mechanism is Config.Routes); it exists so the generic
	// type parameters survive into the huma handlers.
	registerRoutesFn func(api huma.API, bdb *db.DB, r *ResourceConfig)
}

func (r ResourceConfig) hideFields(m map[string]any) map[string]any {
	if r.Schema == nil {
		return m
	}
	for _, f := range r.Schema.HiddenFields {
		delete(m, f)
	}
	return m
}

func (r ResourceConfig) stripReadonlyFields(m map[string]any) map[string]any {
	if r.Schema == nil {
		return m
	}
	for name, f := range r.Schema.Fields {
		if f.IsReadonly {
			delete(m, name)
		}
	}
	return m
}

func (r ResourceConfig) applyDefaults(m map[string]any) map[string]any {
	if r.Schema == nil {
		return m
	}
	for name, f := range r.Schema.Fields {
		if _, ok := m[name]; !ok && f.DefaultValue != nil {
			m[name] = f.DefaultValue
		}
	}
	return m
}

func (r ResourceConfig) hasSchemaField(name string) bool {
	if r.Schema == nil {
		return false
	}
	_, ok := r.Schema.Fields[name]
	return ok
}

func (r ResourceConfig) tableName() string {
	if r.Table != "" {
		return r.Table
	}
	return r.Name
}

func (r ResourceConfig) lookupField() string {
	if r.LookupField != "" {
		return r.LookupField
	}
	if pk := r.pkConfig(); pk != nil {
		return pk.Column
	}
	return "id"
}

func (r ResourceConfig) pkConfig() *schema.PK {
	if r.Schema == nil {
		return nil
	}
	return r.Schema.PK
}

// pkColumn is the brick-managed PK column, or "" when the client supplies
// the PK (AutonamePrompt).
func (r ResourceConfig) pkColumn() string {
	if pk := r.pkConfig(); pk != nil {
		if pk.Autoname.Strategy == schema.AutonamePrompt {
			return ""
		}
		return pk.Column
	}
	return "id"
}

func (r ResourceConfig) pkIsPrompt() bool {
	pk := r.pkConfig()
	return pk != nil && pk.Autoname.Strategy == schema.AutonamePrompt
}

func (r ResourceConfig) sortableFields() []string {
	if r.Schema == nil {
		return nil
	}
	var out []string
	for name, f := range r.Schema.Fields {
		if f.IsSortable {
			out = append(out, name)
		}
	}
	return out
}

func (r ResourceConfig) searchableFields() []string {
	if r.Schema == nil {
		return nil
	}
	var out []string
	for name, f := range r.Schema.Fields {
		if f.IsSearchable {
			out = append(out, name)
		}
	}
	return out
}

// isAllowedSort reports whether a Sort string ("col" or "-col") names a
// sortable column. Anything else — empty, malformed, unknown — is not
// allowed (execList rejects with 400; the db layer ignores as backup).
func isAllowedSort(sort string, sortable []string) bool {
	col := strings.TrimPrefix(sort, "-")
	if col == "" {
		return false
	}
	for i := 0; i < len(col); i++ {
		c := col[i]
		if !(c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	for _, allowed := range sortable {
		if allowed == col {
			return true
		}
	}
	return false
}

// Resource builds a ResourceConfig from codegen types. Typed path only.
func Resource[Row, Response, CreateBody, UpdateBody, ListInput any](
	name, table string,
	s Schema[Row, Response, CreateBody, UpdateBody, ListInput],
) ResourceConfig {
	dynSchema := buildDynamicSchema(s.Fields)
	if s.PK != nil {
		dynSchema.ApplyPK(s.PK)
	}
	r := ResourceConfig{
		Name:        name,
		Table:       table,
		Model:       (*Row)(nil),
		Schema:      dynSchema,
		Operations:  s.Operations,
		Hooks:       s.Hooks,
		Guards:      s.Guards,
		Access:      s.Access,
		LookupField: s.LookupField,
		AutoCreate:  s.AutoCreate,
	}

	r.registerRoutesFn = func(api huma.API, bdb *db.DB, res *ResourceConfig) {
		base := "/api/" + res.Name
		// --- GET /{resource}/{id} ---
		if res.Operations.Enabled("get") {
			huma.Register(api, huma.Operation{
				Tags:        []string{res.Name},
				Method:      http.MethodGet,
				Path:        base + "/{id}",
				OperationID: "get" + title(res.Name),
				Summary:     "Get a " + res.Name,
			}, func(ctx context.Context, input *GetInput) (*GetOutput[Response], error) {
				m, err := execGet(ctx, bdb, *res, input.ID)
				if err != nil {
					return nil, err
				}
				data, _ := json.Marshal(m)
				var out Response
				_ = json.Unmarshal(data, &out)
				return &GetOutput[Response]{Body: out}, nil
			})
		}

		// --- GET /{resource} (List) ---
		if res.Operations.Enabled("list") {
			huma.Register(api, huma.Operation{
				Method:      http.MethodGet,
				Path:        base,
				OperationID: "list" + titlePlural(res.Name),
				Summary:     "List " + res.Name + "s",
				Tags:        []string{res.Name},
			}, func(ctx context.Context, input *ListInput) (*ListOutput[Response], error) {
				opts := any(input).(ListInputer).ToListOptions()
				result, err := execList(ctx, bdb, *res, opts)
				if err != nil {
					return nil, err
				}
				items := make([]Response, len(result.Body.Data))
				for i, m := range result.Body.Data {
					data, _ := json.Marshal(m)
					_ = json.Unmarshal(data, &items[i])
				}
				return &ListOutput[Response]{
					Body: ListResponse[Response]{
						Data:  items,
						Total: result.Body.Total,
						Page:  result.Body.Page,
						Limit: result.Body.Limit,
					},
				}, nil
			})
		}

		// --- POST /{resource} (Create) ---
		if res.Operations.Enabled("create") {
			huma.Register(api, huma.Operation{
				Tags:        []string{res.Name},
				Method:      http.MethodPost,
				Path:        base,
				OperationID: "create" + title(res.Name),
				Summary:     "Create a " + res.Name,
			}, func(ctx context.Context, input *CreateInput[CreateBody]) (*CreateOutput[Response], error) {
				data, _ := json.Marshal(input.Body)
				var body map[string]any
				_ = json.Unmarshal(data, &body)
				m, err := execCreate(ctx, bdb, *res, body)
				if err != nil {
					return nil, err
				}
				respData, _ := json.Marshal(m)
				var out Response
				_ = json.Unmarshal(respData, &out)
				return &CreateOutput[Response]{Body: out}, nil
			})
		}

		// --- PATCH /{resource}/{id} (Update) ---
		if res.Operations.Enabled("update") {
			huma.Register(api, huma.Operation{
				Tags:        []string{res.Name},
				Method:      http.MethodPatch,
				Path:        base + "/{id}",
				OperationID: "update" + title(res.Name),
				Summary:     "Update a " + res.Name,
			}, func(ctx context.Context, input *UpdateInput[UpdateBody]) (*UpdateOutput[Response], error) {
				data, _ := json.Marshal(input.Body)
				var body map[string]any
				_ = json.Unmarshal(data, &body)
				m, err := execUpdate(ctx, bdb, *res, input.ID, body)
				if err != nil {
					return nil, err
				}
				respData, _ := json.Marshal(m)
				var out Response
				_ = json.Unmarshal(respData, &out)
				return &UpdateOutput[Response]{Body: out}, nil
			})
		}

		// --- DELETE /{resource}/{id} ---
		if res.Operations.Enabled("delete") {
			huma.Register(api, huma.Operation{
				Tags:        []string{res.Name},
				Method:      http.MethodDelete,
				Path:        base + "/{id}",
				OperationID: "delete" + title(res.Name),
				Summary:     "Delete a " + res.Name,
			}, func(ctx context.Context, input *DeleteInput) (*struct{}, error) {
				if err := execDelete(ctx, bdb, *res, input.ID); err != nil {
					return nil, err
				}
				return nil, nil
			})
		}
	}

	return r
}

func (b *Brick[TCtx]) registerRoutes(rp *ResourceConfig) {
	if b.db == nil {
		// Unreachable: New errors on nil DB. Kept as a loud guard so a
		// future constructor change cannot silently deregister routes.
		return
	}
	if rp.registerRoutesFn == nil {
		return
	}
	rp.registerRoutesFn(b.api, b.db, rp)
}

// ─── Exec pipelines ───────────────────────────────────────────────────────
// Per-request order, every op: guard Check → validation → guard Filter
// pushdown → single-query exec. Out-of-scope reads/updates/deletes are
// 404, not 403 (no existence oracle).

func execGet(ctx context.Context, bdb *db.DB, r ResourceConfig, id string) (map[string]any, error) {
	guards := opGuards(r, opGet)

	// Session-only checks (e.g., IsAuthenticated) before any DB hit.
	if err := evalGuardsCheck(guards, ctx, nil, nil, 0); err != nil {
		return nil, err
	}

	// Record-scoping filters are pushed into the SELECT — no read-then-check.
	where := collectFilters(guards, ctx)

	m, err := bdb.FindByFieldTableWhere(ctx, r.tableName(), r.lookupField(), id, where)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, NotFound(r.Name + " not found")
		}
		return nil, mapPGError(ctx, r.Name, "get", err)
	}
	if m == nil {
		return nil, NotFound(r.Name + " not found")
	}
	return r.hideFields(m), nil
}

// collectFilters resolves all guard Filter funcs against the current request
// context and returns the merged []db.Where to inject into queries.
func collectFilters(guards []Guard[map[string]any], ctx context.Context) []db.Where {
	if len(guards) == 0 {
		return nil
	}
	ac := AccessCtx[map[string]any]{Context: ctx}
	if appCtx := appCtxFromContext(ctx); appCtx != nil {
		ac.Actor = appCtx.BrickActor()
		ac.Session = appCtx.BrickSession()
	}
	var out []db.Where
	for _, g := range guards {
		if g.Filter == nil {
			continue
		}
		out = append(out, g.Filter(ac)...)
	}
	return out
}

func execCreate(ctx context.Context, bdb *db.DB, r ResourceConfig, body map[string]any) (map[string]any, error) {
	table := r.tableName()
	if err := evalGuardsCheck(opGuards(r, opCreate), ctx, nil, nil, 0); err != nil {
		return nil, err
	}

	body = stripUnknownKeys(r, body)
	body = r.stripReadonlyFields(body)
	// The PK column is autoname-owned: strip even when not marked readonly
	// (AutonamePrompt is the only client-supplied exception).
	if pkCol := r.pkColumn(); pkCol != "" {
		delete(body, pkCol)
	}
	if err := applyFromSources(ctx, r, body); err != nil {
		return nil, err
	}
	body = r.applyDefaults(body)
	stampCreateTimes(r, body)
	if err := validateCreateBody(r, body); err != nil {
		return nil, err
	}

	pk := r.pkConfig()
	retryHash := pk != nil && pk.Autoname.Strategy == schema.AutonameHash

	var record map[string]any
	txErr := bdb.RunInTx(ctx, nil, func(ctx context.Context, txDB *db.DB) error {
		// Autoname runs here — after Check+validation, inside the tx — so
		// rejected creates never burn counters or take advisory locks.
		if pk != nil {
			if err := applyAutoname(ctx, txDB, table, pk, body); err != nil {
				return err
			}
		} else if _, ok := body["id"]; !ok && r.hasSchemaField("id") {
			body["id"] = newUUID()
		}

		if r.Hooks.BeforeCreate != nil {
			hc := HookCtx[map[string]any, map[string]any]{
				ResourceName: r.Name,
				Input:        &body,
				Actor:        actorFromCtx(ctx),
				DB:           txDB,
				Context:      ctx,
			}
			if err := r.Hooks.BeforeCreate(hc); err != nil {
				return err
			}
			body = *hc.Input
		}

		if r.Hooks.Validate != nil {
			if err := r.Hooks.Validate(ValidateCtx{
				ResourceName: r.Name,
				Input:        body,
				Actor:        actorFromCtx(ctx),
				DB:           txDB,
				Context:      ctx,
				op:           opCreate,
			}); err != nil {
				return err
			}
		}

		if err := checkUniquePrecheck(ctx, txDB, r, body, nil); err != nil {
			return err
		}

		inserted, err := txDB.InsertMap(ctx, table, body)
		if err != nil && retryHash && isUniqueViolation(err) {
			// Hash collision: regenerate once and retry; a second
			// collision resolves to 409 below.
			body[pk.Column] = randBase36(pk.Autoname.HashLen)
			inserted, err = txDB.InsertMap(ctx, table, body)
		}
		if err != nil {
			return mapPGError(ctx, r.Name, "create", err)
		}
		record = inserted

		if r.Hooks.AfterCreate != nil {
			if err := r.Hooks.AfterCreate(HookCtx[map[string]any, map[string]any]{
				ResourceName: r.Name,
				Record:       record,
				Actor:        actorFromCtx(ctx),
				DB:           txDB,
				Context:      ctx,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if txErr != nil {
		// Preserve huma.StatusError shape (hook denials, 404/409/422s);
		// anything else is a 500 with a request ID.
		if _, ok := txErr.(huma.StatusError); ok {
			return nil, txErr
		}
		logExecError(ctx, "create "+r.Name, txErr)
		return nil, internalError(requestIDFromCtx(ctx))
	}

	return r.hideFields(record), nil
}

// stampCreateTimes fills created_at/updated_at only when the schema declares
// them (plain tables). Frappe tables use creation/modified, stamped by app
// hooks — brick must not invent columns there.
func stampCreateTimes(r ResourceConfig, body map[string]any) {
	now := time.Now().UTC()
	if r.hasSchemaField("created_at") {
		if _, ok := body["created_at"]; !ok {
			body["created_at"] = now
		}
	}
	if r.hasSchemaField("updated_at") {
		if _, ok := body["updated_at"]; !ok {
			body["updated_at"] = now
		}
	}
}

func execUpdate(ctx context.Context, bdb *db.DB, r ResourceConfig, id string, body map[string]any) (map[string]any, error) {
	guards := opGuards(r, opUpdate)

	if err := evalGuardsCheck(guards, ctx, nil, nil, 0); err != nil {
		return nil, err
	}
	where := collectFilters(guards, ctx)

	body = stripUnknownKeys(r, body)
	body = r.stripReadonlyFields(body)
	// The PK/lookup column is never updatable, even with the prompt strategy.
	delete(body, r.lookupField())
	if err := applyFromSources(ctx, r, body); err != nil {
		return nil, err
	}
	if err := validateUpdateBody(r, body); err != nil {
		return nil, err
	}
	if len(body) == 0 {
		return nil, BadRequest("nothing to update")
	}

	table := r.tableName()
	var m map[string]any
	txErr := bdb.RunInTx(ctx, nil, func(ctx context.Context, txDB *db.DB) error {
		previous, _ := txDB.FindByFieldTableWhere(ctx, table, r.lookupField(), id, where)
		if previous == nil {
			return NotFound(r.Name + " not found")
		}

		if r.Hooks.BeforeUpdate != nil {
			hc := HookCtx[map[string]any, map[string]any]{
				ResourceName: r.Name,
				Input:        &body,
				Record:       previous,
				Previous:     previous,
				Actor:        actorFromCtx(ctx),
				DB:           txDB,
				Context:      ctx,
			}
			if err := r.Hooks.BeforeUpdate(hc); err != nil {
				return err
			}
			body = *hc.Input
		}

		if r.Hooks.Validate != nil {
			if err := r.Hooks.Validate(ValidateCtx{
				ResourceName: r.Name,
				Input:        body,
				Previous:     previous,
				Actor:        actorFromCtx(ctx),
				DB:           txDB,
				Context:      ctx,
				op:           opUpdate,
			}); err != nil {
				return err
			}
		}

		if err := checkUniquePrecheck(ctx, txDB, r, body, previous); err != nil {
			return err
		}

		updated, err := txDB.UpdateByFieldTableWhere(ctx, table, r.lookupField(), id, body, where)
		if err != nil {
			if err == sql.ErrNoRows {
				return NotFound(r.Name + " not found")
			}
			return mapPGError(ctx, r.Name, "update", err)
		}
		if updated == nil {
			return NotFound(r.Name + " not found")
		}
		m = updated

		if r.Hooks.AfterUpdate != nil {
			if err := r.Hooks.AfterUpdate(HookCtx[map[string]any, map[string]any]{
				ResourceName: r.Name,
				Record:       m,
				Previous:     previous,
				Actor:        actorFromCtx(ctx),
				DB:           txDB,
				Context:      ctx,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if txErr != nil {
		if _, ok := txErr.(huma.StatusError); ok {
			return nil, txErr
		}
		logExecError(ctx, "update "+r.Name, txErr)
		return nil, internalError(requestIDFromCtx(ctx))
	}

	return r.hideFields(m), nil
}

func execDelete(ctx context.Context, bdb *db.DB, r ResourceConfig, id string) error {
	guards := opGuards(r, opDelete)

	if err := evalGuardsCheck(guards, ctx, nil, nil, 0); err != nil {
		return err
	}
	where := collectFilters(guards, ctx)

	table := r.tableName()

	txErr := bdb.RunInTx(ctx, nil, func(ctx context.Context, txDB *db.DB) error {
		previous, _ := txDB.FindByFieldTableWhere(ctx, table, r.lookupField(), id, where)
		if previous == nil {
			return NotFound(r.Name + " not found")
		}

		if r.Hooks.BeforeDelete != nil {
			if err := r.Hooks.BeforeDelete(HookCtx[map[string]any, map[string]any]{
				ResourceName: r.Name,
				Record:       previous,
				Actor:        actorFromCtx(ctx),
				DB:           txDB,
				Context:      ctx,
			}); err != nil {
				return err
			}
		}

		n, err := txDB.DeleteByFieldTableWhere(ctx, table, r.lookupField(), id, where)
		if err != nil {
			return mapPGError(ctx, r.Name, "delete", err)
		}
		if n == 0 {
			return NotFound(r.Name + " not found")
		}

		if r.Hooks.AfterDelete != nil {
			if err := r.Hooks.AfterDelete(HookCtx[map[string]any, map[string]any]{
				ResourceName: r.Name,
				Record:       previous,
				Actor:        actorFromCtx(ctx),
				DB:           txDB,
				Context:      ctx,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	if txErr != nil {
		if _, ok := txErr.(huma.StatusError); ok {
			return txErr
		}
		logExecError(ctx, "delete "+r.Name, txErr)
		return internalError(requestIDFromCtx(ctx))
	}

	return nil
}

// execList runs the shared list query logic. Sort outside the schema
// sortable allowlist is a 400 (unknown or malformed). Pagination echoes
// the EFFECTIVE page/limit after clamping (shared consts with db).
func execList(ctx context.Context, bdb *db.DB, r ResourceConfig, opts db.ListOptions) (*struct {
	Body ListResponse[map[string]any]
}, error) {
	guards := opGuards(r, opList)
	if err := evalGuardsCheck(guards, ctx, nil, nil, 0); err != nil {
		return nil, err
	}

	if opts.Sort != "" && !isAllowedSort(opts.Sort, r.sortableFields()) {
		return nil, BadRequest("invalid sort " + opts.Sort)
	}

	page, limit := opts.Page, opts.Limit
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = db.DefaultLimit
	} else if limit > db.MaxLimit {
		limit = db.MaxLimit
	}
	opts.Page = page
	opts.Limit = limit
	opts.Searchable = r.searchableFields()
	opts.Sortable = r.sortableFields()
	// Guard predicates ANDed after user filters: client filters narrow
	// only, never widen. Fresh slice — never alias the caller's.
	filter := make([]db.Where, 0, len(opts.Filter)+2)
	filter = append(filter, opts.Filter...)
	filter = append(filter, collectFilters(guards, ctx)...)
	opts.Filter = filter

	var maps []map[string]any
	var total int64
	if isMapModel(r.Model) {
		rows, n, err := bdb.ListMap(ctx, r.tableName(), opts)
		if err != nil {
			return nil, mapPGError(ctx, r.Name, "list", err)
		}
		maps, total = rows, n
	} else {
		slice := allocSlice(r.Model)
		n, err := bdb.List(ctx, slice, opts)
		if err != nil {
			return nil, mapPGError(ctx, r.Name, "list", err)
		}
		total = n
		maps, _ = toMapSlice(slice)
	}

	data := make([]map[string]any, len(maps))
	for i, m := range maps {
		data[i] = r.hideFields(m)
	}
	return &struct {
		Body ListResponse[map[string]any]
	}{
		Body: ListResponse[map[string]any]{
			Data:  data,
			Total: total,
			Page:  page,
			Limit: limit,
		},
	}, nil
}

// mapPGError maps storage failures: unique violations (SQLSTATE 23505,
// never string matching) → 409; everything else → logged 500 with a
// request ID.
func mapPGError(ctx context.Context, resource, op string, err error) error {
	if isUniqueViolation(err) {
		return Conflict(resource + " already exists")
	}
	logExecError(ctx, op+" "+resource, err)
	return internalError(requestIDFromCtx(ctx))
}

// isUniqueViolation reports PG 23505 by SQLSTATE code inspection.
func isUniqueViolation(err error) bool {
	var pgErr pgdriver.Error
	if errors.As(err, &pgErr) {
		return pgErr.Field('C') == "23505"
	}
	var pgErrPtr *pgdriver.Error
	if errors.As(err, &pgErrPtr) && pgErrPtr != nil {
		return pgErrPtr.Field('C') == "23505"
	}
	return false
}

func isMapModel(model any) bool {
	if model == nil {
		return true
	}
	return reflect.TypeOf(model).Kind() == reflect.Map
}

func actorFromCtx(ctx context.Context) any {
	if appCtx := appCtxFromContext(ctx); appCtx != nil {
		return appCtx.BrickActor()
	}
	return nil
}

// op identifies a CRUD operation for guard composition.
type op int

const (
	opList op = iota
	opGet
	opCreate
	opUpdate
	opDelete
)

// opGuards returns the guards to evaluate for a given CRUD operation:
// uniform Guards (apply to all ops) followed by the per-op Access slot.
func opGuards(r ResourceConfig, o op) []Guard[map[string]any] {
	var perOp []Guard[map[string]any]
	switch o {
	case opList:
		perOp = r.Access.List
	case opGet:
		perOp = r.Access.Get
	case opCreate:
		perOp = r.Access.Create
	case opUpdate:
		perOp = r.Access.Update
	case opDelete:
		perOp = r.Access.Delete
	}
	if len(r.Guards) == 0 {
		return perOp
	}
	if len(perOp) == 0 {
		return r.Guards
	}
	combined := make([]Guard[map[string]any], 0, len(r.Guards)+len(perOp))
	combined = append(combined, r.Guards...)
	combined = append(combined, perOp...)
	return combined
}

// evalGuardsCheck evaluates access guard checks for a CRUD operation.
func evalGuardsCheck(guards []Guard[map[string]any], ctx context.Context, actor any, record map[string]any, rowsAffected int64) error {
	if actor == nil {
		actor = actorFromCtx(ctx)
	}
	ac := AccessCtx[map[string]any]{
		Actor:   actor,
		Record:  record,
		Context: ctx,
	}
	for _, g := range guards {
		if err := g.CheckRowsAffected(ac, rowsAffected); err != nil {
			return err
		}
	}
	return nil
}

func allocSlice(model any) any {
	if model == nil {
		return &[]map[string]any{}
	}
	rv := reflect.TypeOf(model)
	t := rv
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}
	return reflect.New(reflect.SliceOf(t)).Interface()
}

func toMapSlice(slice any) ([]map[string]any, error) {
	if slice == nil {
		return nil, nil
	}
	data, err := json.Marshal(slice)
	if err != nil {
		return nil, err
	}
	var result []map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

func buildDynamicSchema(fields schema.Fields) *schema.DynamicSchema {
	return schema.NewDynamicSchema(fields)
}

func title(s string) string {
	if s == "" {
		return ""
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func titlePlural(s string) string {
	return title(s)
}
