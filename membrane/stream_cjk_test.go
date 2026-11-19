package membrane

import (
	"strings"
	"testing"

	"github.com/Autumn-27/norma/llm"
)

// Final review extra: CJK prose has no ASCII spaces; its punctuation must
// end a token so the stream is not held back to the 1024-byte force flush.
func TestStreamCJKPunctuationDelimits(t *testing.T) {
	e, _ := newTestEngine(t)
	var sb strings.Builder
	for sb.Len() < 480*3 {
		sb.WriteString("这是一个测试，没有空格。")
	}
	text := sb.String()
	runes := []rune(text)[:480]
	text = string(runes)
	var inner []llm.StreamEvent
	for i := 0; i < len(runes); i += 8 {
		inner = append(inner, llm.StreamEvent{Type: llm.SETextDelta, Text: string(runes[i:min(i+8, len(runes))])})
	}
	inner = append(inner, llm.StreamEvent{Type: llm.SEMessageStop})
	p := Wrap(&fakeProvider{events: inner}, e, &memAuditor{}, "kimi")
	got := collect(t, p.Stream(testCtx(), userReq("hi")))
	deltas := 0
	for _, ev := range got {
		if ev.Type == llm.SETextDelta {
			deltas++
		}
	}
	if deltas <= 2 {
		t.Fatalf("480 CJK runes streamed in %d deltas, want more than 2", deltas)
	}
	if m := accumulate(got); m.Content[0].Text != text {
		t.Fatal("text changed")
	}
	for _, r := range "，。、：；！？（）【】《》「」　" {
		if !isStreamDelim(r) {
			t.Errorf("%q is not a stream delimiter", r)
		}
	}
}
