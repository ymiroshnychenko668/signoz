package communitypostgres

import (
	"strings"

	"github.com/uptrace/bun"
	"github.com/uptrace/bun/schema"
)

type formatter struct{ f schema.Formatter }

func (f formatter) path(column, path string) string {
	if path == "" || path == "$" {
		return f.f.FormatQuery("(?)::jsonb", bun.Ident(column))
	}
	return f.f.FormatQuery("jsonb_path_query_first((?)::jsonb, ?::jsonpath)", bun.Ident(column), path)
}
func (f formatter) JSONExtractString(c, p string) []byte {
	return []byte("(" + f.path(c, p) + " #>> '{}')")
}
func (f formatter) JSONExtractMapValue(c, field, key string) []byte {
	return []byte(f.f.FormatQuery("jsonb_extract_path_text((?)::jsonb, ?, ?)", bun.Ident(c), field, key))
}
func (f formatter) JSONType(c, p string) []byte    { return []byte("jsonb_typeof(" + f.path(c, p) + ")") }
func (f formatter) JSONIsArray(c, p string) []byte { return append(f.JSONType(c, p), " = 'array'"...) }
func (f formatter) source(fn, typ, fallback, c, p, alias string) ([]byte, []byte) {
	value := f.path(c, p)
	argument := "CASE WHEN jsonb_typeof(" + value + ") = '" + typ + "' THEN " + value + " ELSE '" + fallback + "'::jsonb END"
	src := fn + "(" + argument + ") AS " + f.f.FormatQuery("?", bun.Ident(alias)) + "(value)"
	return []byte(src), []byte(f.f.FormatQuery("?.value", bun.Ident(alias)))
}
func (f formatter) JSONArrayElements(c, p, alias string) ([]byte, []byte) {
	return f.source("jsonb_array_elements", "array", "[]", c, p, alias)
}
func (f formatter) JSONArrayOfStrings(c, p, alias string) ([]byte, []byte) {
	return f.source("jsonb_array_elements_text", "array", "[]", c, p, alias)
}
func (f formatter) JSONKeys(c, p, alias string) ([]byte, []byte) {
	return f.source("jsonb_object_keys", "object", "{}", c, p, alias)
}
func (f formatter) JSONArrayAgg(expr string) []byte {
	return []byte("COALESCE(jsonb_agg(" + expr + "), '[]'::jsonb)")
}
func (f formatter) JSONArrayLiteral(values ...string) []byte {
	items := make([]string, len(values))
	for i, value := range values {
		items[i] = f.f.FormatQuery("?::text", value)
	}
	return []byte("jsonb_build_array(" + strings.Join(items, ", ") + ")")
}
func (f formatter) TextToJsonColumn(c string) []byte   { return []byte(f.path(c, "")) }
func (f formatter) LowerExpression(expr string) []byte { return []byte("lower(" + expr + ")") }
func (f formatter) EscapeLikePattern(value string) string {
	return strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(value)
}
