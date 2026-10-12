package mihomo

// deepCopyMap returns a recursive copy of a config map so callers can mutate
// the panel payload without touching the caller's model.
func deepCopyMap(src map[string]any) map[string]any {
	if src == nil {
		return map[string]any{}
	}
	out := make(map[string]any, len(src))
	for key, value := range src {
		out[key] = deepCopyValue(value)
	}
	return out
}

func deepCopyValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		return deepCopyMap(typed)
	case []any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = deepCopyValue(item)
		}
		return out
	default:
		return value
	}
}

// MergeCustomConfig layers a locally supplied mihomo document over the
// generated one.
//
// Maps merge recursively and scalars are replaced, with three deliberate
// exceptions that keep the kernel's ordering rules intact:
//   - `rules` is prepended, so a local rule wins over the generated policy;
//   - `proxies` and `listeners` are appended, so local entries are added
//     without dropping the panel's;
//   - everything else follows "custom wins".
func MergeCustomConfig(doc, custom map[string]any) map[string]any {
	if len(custom) == 0 {
		return doc
	}
	if doc == nil {
		doc = map[string]any{}
	}

	for key, customValue := range custom {
		switch key {
		case "rules":
			doc[key] = mergeRuleList(doc[key], customValue)
		case "proxies", "listeners":
			doc[key] = mergeAppendList(doc[key], customValue)
		default:
			if existingMap, ok := doc[key].(map[string]any); ok {
				if customMap, ok := customValue.(map[string]any); ok {
					doc[key] = MergeCustomConfig(existingMap, customMap)
					continue
				}
			}
			doc[key] = customValue
		}
	}
	return doc
}

// mergeRuleList prepends custom rules to the generated ones.
func mergeRuleList(existing, custom any) any {
	customList := toStringList(custom)
	if len(customList) == 0 {
		return existing
	}
	existingList := toStringList(existing)

	return append(customList, existingList...)
}

func mergeAppendList(existing, custom any) any {
	customList := toAnyList(custom)
	if len(customList) == 0 {
		return existing
	}
	existingList := toAnyList(existing)

	return append(existingList, customList...)
}

func toStringList(value any) []string {
	switch typed := value.(type) {
	case []string:
		out := make([]string, len(typed))
		copy(out, typed)
		return out
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}

func toAnyList(value any) []any {
	switch typed := value.(type) {
	case []map[string]any:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = item
		}
		return out
	case []string:
		out := make([]any, len(typed))
		for i, item := range typed {
			out[i] = item
		}
		return out
	case []any:
		out := make([]any, len(typed))
		copy(out, typed)
		return out
	default:
		return nil
	}
}
