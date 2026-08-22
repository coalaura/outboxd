package deliver

import (
	"fmt"
	"strings"
	"time"
)

type debugLogger interface {
	Debugf(format string, values ...any)
}

type debugPhase struct {
	name     string
	duration time.Duration
}

type debugTrace struct {
	started time.Time
	last    time.Time
	phases  []debugPhase
}

func (d *Deliverer) debugf(format string, values ...any) {
	if d.debugLog != nil {
		d.debugLog.Debugf(format, values...)
	}
}

func (d *Deliverer) newDebugTrace() *debugTrace {
	if d.debugLog == nil {
		return nil
	}

	now := time.Now()

	return &debugTrace{started: now, last: now}
}

func (t *debugTrace) mark(name string) {
	if t == nil {
		return
	}

	now := time.Now()

	t.phases = append(t.phases, debugPhase{name: name, duration: now.Sub(t.last)})

	t.last = now
}

func (t *debugTrace) String() string {
	if t == nil {
		return ""
	}

	parts := make([]string, 0, len(t.phases)+1)

	for _, phase := range t.phases {
		parts = append(parts, fmt.Sprintf("%s=%s", phase.name, phase.duration.Round(time.Millisecond)))
	}

	parts = append(parts, fmt.Sprintf("total=%s", time.Since(t.started).Round(time.Millisecond)))

	return strings.Join(parts, " ")
}
