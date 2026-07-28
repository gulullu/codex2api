// Package cybtext extracts user-authored routing and learning text without
// depending on Prompt Filter enforcement budgets or policy configuration.
package cybtext

import (
	"strings"

	"github.com/tidwall/gjson"
)

// ExtractUserSegments returns the current user turn separately from prior
// user-authored history. System, developer, assistant, tool, attachment,
// reasoning, and unknown typed content are excluded.
func ExtractUserSegments(rawBody []byte, endpoint string) (current, history []string) {
	if len(rawBody) == 0 || !gjson.ValidBytes(rawBody) {
		return nil, nil
	}
	switch strings.ToLower(strings.TrimSpace(endpoint)) {
	case "/v1/responses", "/v1/responses/compact":
		current, history = conversationUserSegments(gjson.GetBytes(rawBody, "input"))
		if prompt := userTextFragments(gjson.GetBytes(rawBody, "prompt")); len(prompt) > 0 {
			current = append(current, prompt...)
		}
		if len(current) == 0 {
			fallbackCurrent, fallbackHistory := conversationUserSegments(
				gjson.GetBytes(rawBody, "messages"),
			)
			current = append(current, fallbackCurrent...)
			history = append(history, fallbackHistory...)
		}
	case "/v1/chat/completions", "/v1/messages":
		current, history = conversationUserSegments(gjson.GetBytes(rawBody, "messages"))
	}
	return current, history
}

type inputKind uint8

const (
	inputNone inputKind = iota
	inputExplicitMessage
	inputTextBlock
	inputImplicitMessage
	inputScalar
)

func conversationUserSegments(result gjson.Result) (current, history []string) {
	if !result.Exists() || result.Type == gjson.Null {
		return nil, nil
	}
	if !result.IsArray() {
		if inputKindForItem(result) == inputNone {
			return nil, nil
		}
		return userTextFragments(result), nil
	}

	items := result.Array()
	selected := selectCurrentInputItems(items)
	for index, item := range items {
		if inputKindForItem(item) == inputNone {
			continue
		}
		texts := userTextFragments(item)
		if len(texts) == 0 {
			continue
		}
		if selected[index] {
			current = append(current, texts...)
		} else {
			history = append(history, strings.Join(texts, "\n"))
		}
	}
	return current, history
}

func inputKindForItem(item gjson.Result) inputKind {
	if !item.IsObject() {
		if item.Type == gjson.String {
			return inputScalar
		}
		return inputNone
	}
	if role := strings.ToLower(strings.TrimSpace(item.Get("role").String())); role != "" {
		if role == "user" {
			return inputExplicitMessage
		}
		return inputNone
	}
	switch strings.ToLower(strings.TrimSpace(item.Get("type").String())) {
	case "input_text":
		return inputTextBlock
	case "", "message":
		return inputImplicitMessage
	default:
		return inputNone
	}
}

func selectCurrentInputItems(items []gjson.Result) []bool {
	selected := make([]bool, len(items))
	lastIndex := -1
	lastKind := inputNone
	for index, item := range items {
		if kind := inputKindForItem(item); kind != inputNone {
			lastIndex = index
			lastKind = kind
		}
	}
	if lastIndex < 0 {
		return selected
	}
	for index := lastIndex + 1; index < len(items); index++ {
		if inputClosesDirectPrompt(items[index]) {
			return selected
		}
	}
	selected[lastIndex] = true
	if lastKind != inputTextBlock {
		return selected
	}
	for index := lastIndex - 1; index >= 0; index-- {
		kind := inputKindForItem(items[index])
		if kind == inputTextBlock {
			selected[index] = true
			continue
		}
		if inputItemIsAttachment(items[index]) {
			continue
		}
		break
	}
	return selected
}

func inputClosesDirectPrompt(item gjson.Result) bool {
	if !item.IsObject() {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(item.Get("role").String())) {
	case "assistant", "tool", "function":
		return true
	}
	switch strings.ToLower(strings.TrimSpace(item.Get("type").String())) {
	case "output_text", "refusal",
		"function_call_output", "tool_call_output", "local_shell_call_output", "shell_call_output",
		"apply_patch_call_output", "tool_search_output", "tool_search_call_output", "custom_tool_call_output",
		"mcp_tool_call_output", "computer_call_output", "mcp_call_output", "tool_result",
		"function_call", "tool_call", "local_shell_call", "shell_call", "apply_patch_call",
		"tool_search_call", "custom_tool_call", "mcp_tool_call", "mcp_call", "mcp_list_tools",
		"mcp_approval_request", "mcp_approval_response", "additional_tools", "code_interpreter_call",
		"computer_call", "file_search_call", "image_generation_call", "web_search_call", "tool_use":
		return true
	default:
		return false
	}
}

func inputItemIsAttachment(item gjson.Result) bool {
	if !item.IsObject() || strings.TrimSpace(item.Get("role").String()) != "" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(item.Get("type").String())) {
	case "input_file", "input_image", "image_url", "file", "image", "attachment", "computer_screenshot":
		return true
	default:
		return false
	}
}

func userTextFragments(result gjson.Result) []string {
	if !result.Exists() || result.Type == gjson.Null {
		return nil
	}
	if result.Type == gjson.String {
		if text := strings.TrimSpace(result.String()); text != "" {
			return []string{text}
		}
		return nil
	}
	if result.IsArray() {
		out := make([]string, 0, len(result.Array()))
		for _, item := range result.Array() {
			out = append(out, userTextFragments(item)...)
		}
		return out
	}
	if !result.IsObject() {
		return nil
	}

	itemType := strings.ToLower(strings.TrimSpace(result.Get("type").String()))
	switch itemType {
	case "", "message", "input_text", "text":
		// Explicitly supported user text containers.
	default:
		return nil
	}

	role := strings.ToLower(strings.TrimSpace(result.Get("role").String()))
	if role == "user" || itemType == "message" || itemType == "input_text" {
		if content := result.Get("content"); content.Exists() && content.Type != gjson.Null {
			if out := userTextFragments(content); len(out) > 0 {
				return out
			}
		}
		if text := result.Get("text"); text.Type == gjson.String {
			if value := strings.TrimSpace(text.String()); value != "" {
				return []string{value}
			}
		}
		if itemType == "input_text" {
			if value := result.Get("input"); value.Type == gjson.String {
				if text := strings.TrimSpace(value.String()); text != "" {
					return []string{text}
				}
			}
		}
		return nil
	}

	out := make([]string, 0, 2)
	if text := result.Get("text"); text.Type == gjson.String {
		if value := strings.TrimSpace(text.String()); value != "" {
			out = append(out, value)
		}
	}
	if content := result.Get("content"); content.Exists() && content.Type != gjson.Null {
		out = append(out, userTextFragments(content)...)
	}
	return out
}
