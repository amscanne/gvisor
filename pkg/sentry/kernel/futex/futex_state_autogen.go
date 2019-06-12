// automatically generated by stateify.

package futex

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *bucket) beforeSave() {}
func (x *bucket) save(m state.Map) {
	x.beforeSave()
	if !state.IsZeroValue(x.waiters) { m.Failf("waiters is %v, expected zero", x.waiters) }
}

func (x *bucket) afterLoad() {}
func (x *bucket) load(m state.Map) {
}

func (x *Manager) beforeSave() {}
func (x *Manager) save(m state.Map) {
	x.beforeSave()
	if !state.IsZeroValue(x.privateBuckets) { m.Failf("privateBuckets is %v, expected zero", x.privateBuckets) }
	m.Save("sharedBucket", &x.sharedBucket)
}

func (x *Manager) afterLoad() {}
func (x *Manager) load(m state.Map) {
	m.Load("sharedBucket", &x.sharedBucket)
}

func (x *waiterList) beforeSave() {}
func (x *waiterList) save(m state.Map) {
	x.beforeSave()
	m.Save("head", &x.head)
	m.Save("tail", &x.tail)
}

func (x *waiterList) afterLoad() {}
func (x *waiterList) load(m state.Map) {
	m.Load("head", &x.head)
	m.Load("tail", &x.tail)
}

func (x *waiterEntry) beforeSave() {}
func (x *waiterEntry) save(m state.Map) {
	x.beforeSave()
	m.Save("next", &x.next)
	m.Save("prev", &x.prev)
}

func (x *waiterEntry) afterLoad() {}
func (x *waiterEntry) load(m state.Map) {
	m.Load("next", &x.next)
	m.Load("prev", &x.prev)
}

func init() {
	state.Register("futex.bucket", (*bucket)(nil), state.Fns{Save: (*bucket).save, Load: (*bucket).load})
	state.Register("futex.Manager", (*Manager)(nil), state.Fns{Save: (*Manager).save, Load: (*Manager).load})
	state.Register("futex.waiterList", (*waiterList)(nil), state.Fns{Save: (*waiterList).save, Load: (*waiterList).load})
	state.Register("futex.waiterEntry", (*waiterEntry)(nil), state.Fns{Save: (*waiterEntry).save, Load: (*waiterEntry).load})
}
