# SPDX-License-Identifier: Apache-2.0
"""A small JSON Schema checker (the subset the schemas/ files use): type, required, properties,
additionalProperties (bool or schema), items, enum, const, minimum, maximum, minLength, pattern, minItems, $ref
(#/$defs/<name>), anyOf. It returns one line per problem, with the JSON path."""
import json
import os
import re

import mmcore

SCHEMAS = os.path.join(mmcore.CODE, "schemas")
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def load(name):
    with open(os.path.join(SCHEMAS, name + ".schema.json")) as f:
        return json.load(f)


def _type_ok(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, TYPES[t])


def validate(v, schema, root=None, where="$"):
    root = root or schema
    out = []
    if "$ref" in schema:
        name = schema["$ref"].split("/")[-1]
        return validate(v, root["$defs"][name], root, where)
    if "anyOf" in schema:
        if not any(not validate(v, s, root, where) for s in schema["anyOf"]):
            return ["%s: matches none of anyOf" % where]
    t = schema.get("type")
    if t is not None:
        ts = t if isinstance(t, list) else [t]
        if not any(_type_ok(v, x) for x in ts):
            return ["%s: %r is not %s" % (where, v if not isinstance(v, (dict, list)) else type(v).__name__, "|".join(ts))]
    if "enum" in schema and v not in schema["enum"]:
        out.append("%s: %r not in %s" % (where, v, schema["enum"]))
    if "const" in schema and v != schema["const"]:
        out.append("%s: %r is not %r" % (where, v, schema["const"]))
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        if "minimum" in schema and v < schema["minimum"]:
            out.append("%s: %r < %r" % (where, v, schema["minimum"]))
        if "maximum" in schema and v > schema["maximum"]:
            out.append("%s: %r > %r" % (where, v, schema["maximum"]))
    if isinstance(v, str):
        if "minLength" in schema and len(v) < schema["minLength"]:
            out.append("%s: shorter than %d" % (where, schema["minLength"]))
        if "pattern" in schema and not re.search(schema["pattern"], v):
            out.append("%s: %r does not match %s" % (where, v[:60], schema["pattern"]))
    if isinstance(v, list):
        if "minItems" in schema and len(v) < schema["minItems"]:
            out.append("%s: fewer than %d items" % (where, schema["minItems"]))
        if "items" in schema:
            for i, x in enumerate(v):
                out += validate(x, schema["items"], root, "%s[%d]" % (where, i))
    if isinstance(v, dict):
        for k in schema.get("required", []):
            if k not in v:
                out.append("%s: %s is missing" % (where, k))
        props = schema.get("properties", {})
        extra = schema.get("additionalProperties", True)
        for k, x in v.items():
            if k in props:
                out += validate(x, props[k], root, "%s.%s" % (where, k))
            elif extra is False:
                out.append("%s: unknown key %s" % (where, k))
            elif isinstance(extra, dict):
                out += validate(x, extra, root, "%s.%s" % (where, k))
    return out
