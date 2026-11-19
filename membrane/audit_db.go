package membrane

import (
	"context"
	"errors"

	"github.com/Autumn-27/artex/db"
)

// EventAppender is the part of *db.DB the DB auditor needs.
type EventAppender interface {
	AppendMembraneEvent(ev *db.MembraneEvent) error
}

// DBAuditor writes audit events to the hash-chained membrane_events table.
// A write error is returned to the caller, which blocks the request (R13).
type DBAuditor struct {
	DB EventAppender
}

// NewDBAuditor returns an Auditor over d.
func NewDBAuditor(d EventAppender) *DBAuditor { return &DBAuditor{DB: d} }

// Record appends ev. It carries counts, flags and hashes only, never
// originals.
func (a *DBAuditor) Record(_ context.Context, ev Event) error {
	if a == nil || a.DB == nil {
		return errors.New("membrane audit: no database")
	}
	return a.DB.AppendMembraneEvent(toDBEvent(ev))
}

func toDBEvent(ev Event) *db.MembraneEvent {
	counts := make(map[string]int, len(ev.Report.Counts))
	for k, v := range ev.Report.Counts {
		counts[string(k)] = v
	}
	return &db.MembraneEvent{
		TaskID:        ev.TaskID,
		Session:       ev.Session,
		Role:          ev.Role,
		Profile:       ev.Profile,
		Direction:     ev.Direction,
		Counts:        counts,
		Enrolled:      ev.Report.Enrolled,
		Flags:         append([]string(nil), ev.Report.Flags...),
		Blocked:       ev.Blocked,
		BlockReason:   ev.BlockReason,
		RequestSHA256: ev.RequestSHA256,
	}
}
