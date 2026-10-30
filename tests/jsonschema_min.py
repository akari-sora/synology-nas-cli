"""Minimal JSON Schema validator for the tests (type, properties, required, additionalProperties, items,
enum, minimum, oneOf/anyOf, local $ref)."""

TYPES = {"object": dict, "array": list, "string": str, "boolean": bool, "null": type(None)}


def is_type(v, t):
    if t == "integer":
        return isinstance(v, int) and not isinstance(v, bool)
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    return isinstance(v, TYPES[t])


def validate(v, s, root, path="$"):
    errs = []
    if "$ref" in s:
        node = root
        for part in s["$ref"].lstrip("#/").split("/"):
            node = node[part]
        return validate(v, node, root, path)
    if "type" in s:
        ts = s["type"] if isinstance(s["type"], list) else [s["type"]]
        if not any(is_type(v, t) for t in ts):
            return [f"{path}: {type(v).__name__} is not {ts}"]
    if "enum" in s and v not in s["enum"]:
        errs.append(f"{path}: {v!r} not in {s['enum']}")
    if "minimum" in s and isinstance(v, (int, float)) and v < s["minimum"]:
        errs.append(f"{path}: {v} < {s['minimum']}")
    for key in ("oneOf", "anyOf"):
        if key in s:
            ok_n = sum(1 for sub in s[key] if not validate(v, sub, root, path))
            if ok_n == 0 or (key == "oneOf" and ok_n > 1):
                errs.append(f"{path}: {key} matched {ok_n}")
    if isinstance(v, dict):
        for k in s.get("required", []):
            if k not in v:
                errs.append(f"{path}: missing {k}")
        props = s.get("properties", {})
        for k, sub in v.items():
            if k in props:
                errs += validate(sub, props[k], root, f"{path}.{k}")
            elif s.get("additionalProperties") is False:
                errs.append(f"{path}: unexpected {k}")
    if isinstance(v, list) and "items" in s:
        for i, x in enumerate(v):
            errs += validate(x, s["items"], root, f"{path}[{i}]")
    return errs
