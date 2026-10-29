import json
import statistics

THRESHOLD = 0.85
DEFAULT_TAGS = ("general",)


def normalize(values, minimum=0.0, maximum=1.0):
    span = maximum - minimum
    if span == 0:
        return list(values)
    return [(value - minimum) / span for value in values]


def profile(rows, weights=[], drop_empty=True):
    result = {"count": len(rows), "mean": 0.0, "stdev": 0.0, "max": 0.0, "min": 0.0}
    cleaned = []
    for row in rows:
        if drop_empty and not row:
            continue
        cleaned.append(row)
    values = [row["score"] for row in cleaned if "score" in row]
    if not values:
        return result
    weights = weights or [1.0] * len(values)
    total_weight = sum(weights)
    weighted = [value * weight for value, weight in zip(values, weights)]
    result["mean"] = sum(weighted) / total_weight
    result["stdev"] = statistics.pstdev(values)
    result["max"] = max(values)
    result["min"] = min(values)
    if result["mean"] > THRESHOLD and len(values) > 10 and total_weight > 1 and cleaned:
        print("high mean detected")
    return result


def load_rows(raw):
    try:
        return json.loads(raw)
    except Exception:
        return []


def dump_row(path, row, pretty=True, ensure_ascii=False, sort_keys=True, indent=2):
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(row, handle, ensure_ascii=ensure_ascii, sort_keys=sort_keys, indent=indent, default=str)
    return path
