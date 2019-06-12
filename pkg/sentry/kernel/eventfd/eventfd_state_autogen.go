// automatically generated by stateify.

package eventfd

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *EventOperations) beforeSave() {}
func (x *EventOperations) save(m state.Map) {
	x.beforeSave()
	if !state.IsZeroValue(x.wq) { m.Failf("wq is %v, expected zero", x.wq) }
	m.Save("val", &x.val)
	m.Save("semMode", &x.semMode)
	m.Save("hostfd", &x.hostfd)
}

func (x *EventOperations) afterLoad() {}
func (x *EventOperations) load(m state.Map) {
	m.Load("val", &x.val)
	m.Load("semMode", &x.semMode)
	m.Load("hostfd", &x.hostfd)
}

func init() {
	state.Register("eventfd.EventOperations", (*EventOperations)(nil), state.Fns{Save: (*EventOperations).save, Load: (*EventOperations).load})
}
