package appliance

import "time"

type MaintenanceWindow struct{ StartMinuteUTC, EndMinuteUTC uint16 }

var DefaultMaintenanceWindow = MaintenanceWindow{StartMinuteUTC: 120, EndMinuteUTC: 240}

func (w MaintenanceWindow) Valid() bool {
	return w.StartMinuteUTC < 1440 && w.EndMinuteUTC < 1440 && w.StartMinuteUTC != w.EndMinuteUTC
}
func (w MaintenanceWindow) Allows(t time.Time) bool {
	if !w.Valid() || t.IsZero() {
		return false
	}
	t = t.UTC()
	minute := uint16(t.Hour()*60 + t.Minute())
	if w.StartMinuteUTC < w.EndMinuteUTC {
		return minute >= w.StartMinuteUTC && minute < w.EndMinuteUTC
	}
	return minute >= w.StartMinuteUTC || minute < w.EndMinuteUTC
}
