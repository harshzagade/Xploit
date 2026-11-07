"""OpenAPI/Swagger spec seeding for the crawler.

Many APIs expose no HTML page linking to their routes, so a pure
link-crawl never probes them. When a target serves ``/openapi.json``
or ``/swagger.json``, :func:`extract_openapi_paths` turns the spec's
declared paths into crawl entry points:

- OpenAPI 3: ``servers[0].url`` is the base (relative server URLs
  resolve against the target; ``{variable}`` placeholders take their
  default, or the first enum value when no default is given).
- Swagger 2: ``schemes[0]://host + basePath`` is the base, falling back
  to the target URL when the spec names no host.
- Path templates (``/users/{id}``) are filled with ``"1"`` so the seeded
  URL is fetchable; declared ``in: query`` parameters (path-level and
  per-operation) are appended with the placeholder value ``"xploit"``,
  matching the form-field default the crawler already uses.
- Anything malformed (non-dict spec, missing ``paths``, non-string
  keys, unparseable server URL) yields ``[]`` — a broken spec must
  never break the crawl, and the caller still applies its own
  same-origin/scope/exclude filters to every seeded URL.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlencode

_PATH_PARAM_RE = re.compile(r"\{[^}/]+\}")
_SERVER_VAR_RE = re.compile(r"\{([^}/]+)\}")

_PLACEHOLDER_PATH = "1"
_PLACEHOLDER_QUERY = "xploit"

# Operations whose bodies are worth probing. GET/DELETE/HEAD bodies are
# vanishingly rare in real APIs and most servers ignore them.
_JSON_BODY_METHODS = ("post", "put", "patch")


@dataclass
class JsonTarget:
    """One API operation that accepts a JSON request body: where it posts,
    how, and its declared body fields with placeholder values (``"xploit"``,
    matching the form-field default the crawler already uses)."""
    url: str
    method: str
    fields: dict[str, str] = field(default_factory=dict)


def _fill_path_template(path: str) -> str:
    """Replace ``{param}`` segments with a fetchable placeholder."""
    return _PATH_PARAM_RE.sub(_PLACEHOLDER_PATH, path)


def _server_var_value(spec: object) -> str | None:
    """A server-variable value as a string, or None when unusable.

    YAML specs type their scalars, so a numeric default/enum (``default:
    1``) is an int, not a string — accept ints/floats too. Booleans are
    not meaningful variable values.
    """
    if isinstance(spec, str):
        return spec
    if isinstance(spec, (int, float)) and not isinstance(spec, bool):
        return str(spec)
    return None


def _resolve_server_url(server: object, base_url: str) -> str | None:
    """Resolve one OpenAPI 3 server entry against the target URL.

    Returns None when the entry is unusable (not a dict, no URL, or a
    template variable with neither a default nor enum values).
    """
    if not isinstance(server, dict):
        return None
    raw = server.get("url")
    if not isinstance(raw, str) or not raw:
        return None
    variables = server.get("variables")
    if isinstance(variables, dict):
        for name in _SERVER_VAR_RE.findall(raw):
            spec = variables.get(name)
            replacement = None
            if isinstance(spec, dict):
                replacement = _server_var_value(spec.get("default"))
                if replacement is None and isinstance(spec.get("enum"), list) \
                        and spec["enum"]:
                    replacement = _server_var_value(spec["enum"][0])
            if replacement is None:
                return None
            raw = raw.replace("{" + name + "}", replacement)
    elif _SERVER_VAR_RE.search(raw):
        return None
    try:
        return urljoin(base_url, raw)
    except ValueError:
        return None


def _spec_base_url(spec: dict, base_url: str) -> str:
    """Best-effort base URL for a spec's paths (always absolute)."""
    if isinstance(spec.get("servers"), list) and spec["servers"]:
        for server in spec["servers"]:
            resolved = _resolve_server_url(server, base_url)
            if resolved is not None:
                return resolved
    if isinstance(spec.get("host"), str) and spec["host"]:
        # Swagger 2: schemes[0]://host + basePath.
        schemes = spec.get("schemes")
        scheme = "https"
        if isinstance(schemes, list) and schemes:
            first = schemes[0]
            if isinstance(first, str) and first in ("http", "https"):
                scheme = first
        base_path = spec.get("basePath")
        path = base_path if isinstance(base_path, str) else ""
        try:
            return urljoin(f"{scheme}://{spec['host']}", path or "/")
        except ValueError:
            pass
    return base_url


def _query_params(operation: object) -> list[tuple[str, str]]:
    """Declared ``in: query`` parameter names of one operation object."""
    params: list[tuple[str, str]] = []
    if not isinstance(operation, dict):
        return params
    raw = operation.get("parameters")
    if not isinstance(raw, list):
        return params
    for param in raw:
        if isinstance(param, dict) and param.get("in") == "query":
            name = param.get("name")
            if isinstance(name, str) and name:
                params.append((name, _PLACEHOLDER_QUERY))
    return params


def _resolve_ref(spec: dict, schema: object, _seen: frozenset | None = None) -> object:
    """Resolve a local ``$ref`` (``#/components/schemas/<Name>``) one hop.

    Follows a chain of refs (a referenced schema may itself be a ref) with
    a cycle guard; anything unresolvable returns the schema as-is so the
    caller sees no properties instead of crashing.
    """
    seen = _seen or frozenset()
    current = schema
    while isinstance(current, dict) and isinstance(current.get("$ref"), str):
        ref = current["$ref"]
        if ref in seen or not ref.startswith("#/"):
            return current
        seen = seen | {ref}
        node: object = spec
        for part in ref[2:].split("/"):
            if not isinstance(node, dict) or part not in node:
                return current
            node = node[part]
        current = node
    return current


def _schema_properties(spec: dict, schema: object) -> dict[str, object]:
    """Property-name map of a schema object, resolving $refs and allOf."""
    schema = _resolve_ref(spec, schema)
    if not isinstance(schema, dict):
        return {}
    props: dict[str, object] = {}
    raw = schema.get("properties")
    if isinstance(raw, dict):
        props.update(raw)
    # allOf: merge each subschema's properties (first wins on collisions).
    all_of = schema.get("allOf")
    if isinstance(all_of, list):
        for sub in all_of:
            for name, sub_schema in _schema_properties(spec, sub).items():
                props.setdefault(name, sub_schema)
    return props


def _json_body_fields(spec: dict, operation: object) -> dict[str, str]:
    """Declared JSON body field names of one operation, or {}.

    Reads ``requestBody.content["application/json"]`` (plus vendor
    ``*+json`` types) and returns each schema property name with the
    placeholder value ``"xploit"``. No JSON content, no schema, or no
    properties means the operation takes no JSON body.
    """
    if not isinstance(operation, dict):
        return {}
    request_body = operation.get("requestBody")
    if not isinstance(request_body, dict):
        return {}
    content = request_body.get("content")
    if not isinstance(content, dict):
        return {}
    schema = None
    for media_type, media in content.items():
        if not isinstance(media_type, str) or not isinstance(media, dict):
            continue
        if media_type == "application/json" or media_type.endswith("+json"):
            schema = media.get("schema")
            break
    if schema is None:
        return {}
    return {name: _PLACEHOLDER_QUERY
            for name in _schema_properties(spec, schema)}


def extract_json_targets(spec: object, base_url: str) -> list[JsonTarget]:
    """JSON-body operations declared by an OpenAPI/Swagger spec.

    ``base_url`` is the scan target (same base resolution as
    :func:`extract_openapi_paths`). Only POST/PUT/PATCH operations with a
    declared ``application/json`` requestBody schema are returned, in spec
    order; path templates are filled with ``"1"`` and declared query
    parameters are appended with ``"xploit"``, exactly like the seeded
    entry-point URLs. Malformed specs yield ``[]`` — a broken spec must
    never break the crawl.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _spec_base_url(spec, base_url).rstrip("/")
    targets: list[JsonTarget] = []
    seen: set[tuple[str, str]] = set()
    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not raw_path:
            continue
        if not isinstance(item, dict):
            continue
        filled = _fill_path_template(raw_path)
        url = base + "/" + filled.lstrip("/")
        path_query: list[tuple[str, str]] = _query_params(item)
        for method, operation in item.items():
            if method.lower() not in _JSON_BODY_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            fields = _json_body_fields(spec, operation)
            if not fields:
                continue
            # Path-level parameters apply to every operation; per-operation
            # parameters add to them (same name: first wins). Built fresh
            # per operation so one operation's params never leak into the
            # next operation's URL.
            query = list(path_query)
            for name, value in _query_params(operation):
                if name not in {n for n, _ in query}:
                    query.append((name, value))
            target_url = url
            if query:
                target_url = url + "?" + urlencode(query)
            key = (target_url, method.upper())
            if key in seen:
                continue
            seen.add(key)
            targets.append(JsonTarget(url=target_url, method=method.upper(),
                                      fields=dict(fields)))
    return targets


def extract_openapi_paths(spec: object, base_url: str) -> list[str]:
    """Seed URLs declared by an OpenAPI/Swagger spec, in spec order.

    ``base_url`` is the scan target (used to resolve relative server
    URLs and as the fallback base). Returns ``[]`` for any spec that
    is not a dict with a dict ``paths`` member. Duplicates are dropped
    (first occurrence wins); the caller applies scope/exclude filters.
    """
    if not isinstance(spec, dict):
        return []
    paths = spec.get("paths")
    if not isinstance(paths, dict):
        return []
    base = _spec_base_url(spec, base_url).rstrip("/")
    seeded: list[str] = []
    seen: set[str] = set()
    for raw_path, item in paths.items():
        if not isinstance(raw_path, str) or not raw_path:
            continue
        if not isinstance(item, dict):
            continue
        filled = _fill_path_template(raw_path)
        url = base + "/" + filled.lstrip("/")
        # Path-level parameters apply to every operation on this path;
        # per-operation parameters add to them (same name: first wins).
        query: list[tuple[str, str]] = _query_params(item)
        for operation in item.values():
            for name, value in _query_params(operation):
                if name not in {n for n, _ in query}:
                    query.append((name, value))
        if query:
            url = url + "?" + urlencode(query)
        if url not in seen:
            seen.add(url)
            seeded.append(url)
    return seeded
