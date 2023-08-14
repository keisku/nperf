package process

import (
	"context"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/process"
)

type Monitor struct {
	processes sync.Map // key: pid, value: proc
}

type proc struct {
	Name      string
	IsZombie  bool
	ExpiredAt time.Time
}

func (m *Monitor) Run(ctx context.Context) {
	// To avoid the cache from growing infinitely, delete the expired process cache constantly.
	deleteCacheInterval := time.NewTicker(30 * time.Second)
	for {
		select {
		case <-ctx.Done():
			deleteCacheInterval.Stop()
			return
		case <-deleteCacheInterval.C:
			m.processes.Range(func(k, v any) bool {
				pid := k.(int32)
				_, err := process.NewProcess(pid)
				if err != nil {
					// When the process is not found, delete it from the cache.
					m.processes.Delete(pid)
					return true
				}
				proc := v.(proc)
				if proc.ExpiredAt.Before(time.Now()) {
					m.processes.Delete(pid)
				}
				return true
			})
		}
	}
}

// NameById returns the process name by the given pid.
func (m *Monitor) NameById(pid int32) (name string, isZombie bool, err error) {
	if existedProc, ok := m.processes.Load(pid); ok {
		p := existedProc.(proc)
		if p.ExpiredAt.After(time.Now()) {
			return p.Name, p.IsZombie, nil
		}
		// If the process is expired, try to get the process name from /proc again.
	}
	p, err := process.NewProcess(pid)
	if err != nil {
		return "", false, err
	}
	name, err = p.Name()
	if err != nil {
		return "", false, err
	}
	statuses, err := p.Status()
	if err != nil {
		return "", false, err
	}
	for _, status := range statuses {
		if status == process.Zombie {
			isZombie = true
		}
	}
	m.processes.Store(pid, proc{
		Name:      name,
		IsZombie:  isZombie,
		ExpiredAt: time.Now().Add(5 * time.Minute),
	})
	return name, isZombie, nil
}
