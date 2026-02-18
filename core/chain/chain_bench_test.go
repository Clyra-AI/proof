package chain

import (
	"testing"
	"time"

	"github.com/Clyra-AI/proof/core/record"
)

func BenchmarkAppendAndVerify(b *testing.B) {
	for i := 0; i < b.N; i++ {
		c := New("bench", time.Now().UTC())
		for j := 0; j < 100; j++ {
			r, _ := record.New(record.RecordOpts{
				Timestamp:     time.Date(2026, 2, 17, 12, 0, 0, 0, time.UTC),
				Source:        "bench",
				SourceProduct: "bench",
				Type:          "decision",
				Event:         map[string]any{"j": j},
			})
			_ = Append(c, r)
		}
		_, _ = Verify(c)
	}
}
