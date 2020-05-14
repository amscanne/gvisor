// automatically generated by stateify.

package pgalloc

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *EvictableRange) beforeSave() {}
func (x *EvictableRange) save(m state.Map) {
	x.beforeSave()
	m.Save("Start", &x.Start)
	m.Save("End", &x.End)
}

func (x *EvictableRange) afterLoad() {}
func (x *EvictableRange) load(m state.Map) {
	m.Load("Start", &x.Start)
	m.Load("End", &x.End)
}

func (x *evictableRangeSet) beforeSave() {}
func (x *evictableRangeSet) save(m state.Map) {
	x.beforeSave()
	var root *evictableRangeSegmentDataSlices = x.saveRoot()
	m.SaveValue("root", root)
}

func (x *evictableRangeSet) afterLoad() {}
func (x *evictableRangeSet) load(m state.Map) {
	m.LoadValue("root", new(*evictableRangeSegmentDataSlices), func(y interface{}) { x.loadRoot(y.(*evictableRangeSegmentDataSlices)) })
}

func (x *evictableRangenode) beforeSave() {}
func (x *evictableRangenode) save(m state.Map) {
	x.beforeSave()
	m.Save("nrSegments", &x.nrSegments)
	m.Save("parent", &x.parent)
	m.Save("parentIndex", &x.parentIndex)
	m.Save("hasChildren", &x.hasChildren)
	m.Save("keys", &x.keys)
	m.Save("values", &x.values)
	m.Save("children", &x.children)
}

func (x *evictableRangenode) afterLoad() {}
func (x *evictableRangenode) load(m state.Map) {
	m.Load("nrSegments", &x.nrSegments)
	m.Load("parent", &x.parent)
	m.Load("parentIndex", &x.parentIndex)
	m.Load("hasChildren", &x.hasChildren)
	m.Load("keys", &x.keys)
	m.Load("values", &x.values)
	m.Load("children", &x.children)
}

func (x *evictableRangeSegmentDataSlices) beforeSave() {}
func (x *evictableRangeSegmentDataSlices) save(m state.Map) {
	x.beforeSave()
	m.Save("Start", &x.Start)
	m.Save("End", &x.End)
	m.Save("Values", &x.Values)
}

func (x *evictableRangeSegmentDataSlices) afterLoad() {}
func (x *evictableRangeSegmentDataSlices) load(m state.Map) {
	m.Load("Start", &x.Start)
	m.Load("End", &x.End)
	m.Load("Values", &x.Values)
}

func (x *usageInfo) beforeSave() {}
func (x *usageInfo) save(m state.Map) {
	x.beforeSave()
	m.Save("kind", &x.kind)
	m.Save("knownCommitted", &x.knownCommitted)
	m.Save("refs", &x.refs)
}

func (x *usageInfo) afterLoad() {}
func (x *usageInfo) load(m state.Map) {
	m.Load("kind", &x.kind)
	m.Load("knownCommitted", &x.knownCommitted)
	m.Load("refs", &x.refs)
}

func (x *usageSet) beforeSave() {}
func (x *usageSet) save(m state.Map) {
	x.beforeSave()
	var root *usageSegmentDataSlices = x.saveRoot()
	m.SaveValue("root", root)
}

func (x *usageSet) afterLoad() {}
func (x *usageSet) load(m state.Map) {
	m.LoadValue("root", new(*usageSegmentDataSlices), func(y interface{}) { x.loadRoot(y.(*usageSegmentDataSlices)) })
}

func (x *usagenode) beforeSave() {}
func (x *usagenode) save(m state.Map) {
	x.beforeSave()
	m.Save("nrSegments", &x.nrSegments)
	m.Save("parent", &x.parent)
	m.Save("parentIndex", &x.parentIndex)
	m.Save("hasChildren", &x.hasChildren)
	m.Save("keys", &x.keys)
	m.Save("values", &x.values)
	m.Save("children", &x.children)
}

func (x *usagenode) afterLoad() {}
func (x *usagenode) load(m state.Map) {
	m.Load("nrSegments", &x.nrSegments)
	m.Load("parent", &x.parent)
	m.Load("parentIndex", &x.parentIndex)
	m.Load("hasChildren", &x.hasChildren)
	m.Load("keys", &x.keys)
	m.Load("values", &x.values)
	m.Load("children", &x.children)
}

func (x *usageSegmentDataSlices) beforeSave() {}
func (x *usageSegmentDataSlices) save(m state.Map) {
	x.beforeSave()
	m.Save("Start", &x.Start)
	m.Save("End", &x.End)
	m.Save("Values", &x.Values)
}

func (x *usageSegmentDataSlices) afterLoad() {}
func (x *usageSegmentDataSlices) load(m state.Map) {
	m.Load("Start", &x.Start)
	m.Load("End", &x.End)
	m.Load("Values", &x.Values)
}

func init() {
	state.Register("pkg/sentry/pgalloc.EvictableRange", (*EvictableRange)(nil), state.Fns{Save: (*EvictableRange).save, Load: (*EvictableRange).load})
	state.Register("pkg/sentry/pgalloc.evictableRangeSet", (*evictableRangeSet)(nil), state.Fns{Save: (*evictableRangeSet).save, Load: (*evictableRangeSet).load})
	state.Register("pkg/sentry/pgalloc.evictableRangenode", (*evictableRangenode)(nil), state.Fns{Save: (*evictableRangenode).save, Load: (*evictableRangenode).load})
	state.Register("pkg/sentry/pgalloc.evictableRangeSegmentDataSlices", (*evictableRangeSegmentDataSlices)(nil), state.Fns{Save: (*evictableRangeSegmentDataSlices).save, Load: (*evictableRangeSegmentDataSlices).load})
	state.Register("pkg/sentry/pgalloc.usageInfo", (*usageInfo)(nil), state.Fns{Save: (*usageInfo).save, Load: (*usageInfo).load})
	state.Register("pkg/sentry/pgalloc.usageSet", (*usageSet)(nil), state.Fns{Save: (*usageSet).save, Load: (*usageSet).load})
	state.Register("pkg/sentry/pgalloc.usagenode", (*usagenode)(nil), state.Fns{Save: (*usagenode).save, Load: (*usagenode).load})
	state.Register("pkg/sentry/pgalloc.usageSegmentDataSlices", (*usageSegmentDataSlices)(nil), state.Fns{Save: (*usageSegmentDataSlices).save, Load: (*usageSegmentDataSlices).load})
}
