// automatically generated by stateify.

package fsutil

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *DirtySet) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.DirtySet"
}

func (x *DirtySet) StateFields() []string {
	return []string{
		"root",
	}
}

func (x *DirtySet) beforeSave() {}

func (x *DirtySet) StateSave(m state.Sink) {
	x.beforeSave()
	var root *DirtySegmentDataSlices = x.saveRoot()
	m.SaveValue(0, root)
}

func (x *DirtySet) afterLoad() {}

func (x *DirtySet) StateLoad(m state.Source) {
	m.LoadValue(0, new(*DirtySegmentDataSlices), func(y interface{}) { x.loadRoot(y.(*DirtySegmentDataSlices)) })
}

func (x *Dirtynode) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.Dirtynode"
}

func (x *Dirtynode) StateFields() []string {
	return []string{
		"nrSegments",
		"parent",
		"parentIndex",
		"hasChildren",
		"maxGap",
		"keys",
		"values",
		"children",
	}
}

func (x *Dirtynode) beforeSave() {}

func (x *Dirtynode) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.nrSegments)
	m.Save(1, &x.parent)
	m.Save(2, &x.parentIndex)
	m.Save(3, &x.hasChildren)
	m.Save(4, &x.maxGap)
	m.Save(5, &x.keys)
	m.Save(6, &x.values)
	m.Save(7, &x.children)
}

func (x *Dirtynode) afterLoad() {}

func (x *Dirtynode) StateLoad(m state.Source) {
	m.Load(0, &x.nrSegments)
	m.Load(1, &x.parent)
	m.Load(2, &x.parentIndex)
	m.Load(3, &x.hasChildren)
	m.Load(4, &x.maxGap)
	m.Load(5, &x.keys)
	m.Load(6, &x.values)
	m.Load(7, &x.children)
}

func (x *DirtySegmentDataSlices) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.DirtySegmentDataSlices"
}

func (x *DirtySegmentDataSlices) StateFields() []string {
	return []string{
		"Start",
		"End",
		"Values",
	}
}

func (x *DirtySegmentDataSlices) beforeSave() {}

func (x *DirtySegmentDataSlices) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.Start)
	m.Save(1, &x.End)
	m.Save(2, &x.Values)
}

func (x *DirtySegmentDataSlices) afterLoad() {}

func (x *DirtySegmentDataSlices) StateLoad(m state.Source) {
	m.Load(0, &x.Start)
	m.Load(1, &x.End)
	m.Load(2, &x.Values)
}

func (x *FileRangeSet) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.FileRangeSet"
}

func (x *FileRangeSet) StateFields() []string {
	return []string{
		"root",
	}
}

func (x *FileRangeSet) beforeSave() {}

func (x *FileRangeSet) StateSave(m state.Sink) {
	x.beforeSave()
	var root *FileRangeSegmentDataSlices = x.saveRoot()
	m.SaveValue(0, root)
}

func (x *FileRangeSet) afterLoad() {}

func (x *FileRangeSet) StateLoad(m state.Source) {
	m.LoadValue(0, new(*FileRangeSegmentDataSlices), func(y interface{}) { x.loadRoot(y.(*FileRangeSegmentDataSlices)) })
}

func (x *FileRangenode) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.FileRangenode"
}

func (x *FileRangenode) StateFields() []string {
	return []string{
		"nrSegments",
		"parent",
		"parentIndex",
		"hasChildren",
		"maxGap",
		"keys",
		"values",
		"children",
	}
}

func (x *FileRangenode) beforeSave() {}

func (x *FileRangenode) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.nrSegments)
	m.Save(1, &x.parent)
	m.Save(2, &x.parentIndex)
	m.Save(3, &x.hasChildren)
	m.Save(4, &x.maxGap)
	m.Save(5, &x.keys)
	m.Save(6, &x.values)
	m.Save(7, &x.children)
}

func (x *FileRangenode) afterLoad() {}

func (x *FileRangenode) StateLoad(m state.Source) {
	m.Load(0, &x.nrSegments)
	m.Load(1, &x.parent)
	m.Load(2, &x.parentIndex)
	m.Load(3, &x.hasChildren)
	m.Load(4, &x.maxGap)
	m.Load(5, &x.keys)
	m.Load(6, &x.values)
	m.Load(7, &x.children)
}

func (x *FileRangeSegmentDataSlices) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.FileRangeSegmentDataSlices"
}

func (x *FileRangeSegmentDataSlices) StateFields() []string {
	return []string{
		"Start",
		"End",
		"Values",
	}
}

func (x *FileRangeSegmentDataSlices) beforeSave() {}

func (x *FileRangeSegmentDataSlices) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.Start)
	m.Save(1, &x.End)
	m.Save(2, &x.Values)
}

func (x *FileRangeSegmentDataSlices) afterLoad() {}

func (x *FileRangeSegmentDataSlices) StateLoad(m state.Source) {
	m.Load(0, &x.Start)
	m.Load(1, &x.End)
	m.Load(2, &x.Values)
}

func (x *FrameRefSet) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.FrameRefSet"
}

func (x *FrameRefSet) StateFields() []string {
	return []string{
		"root",
	}
}

func (x *FrameRefSet) beforeSave() {}

func (x *FrameRefSet) StateSave(m state.Sink) {
	x.beforeSave()
	var root *FrameRefSegmentDataSlices = x.saveRoot()
	m.SaveValue(0, root)
}

func (x *FrameRefSet) afterLoad() {}

func (x *FrameRefSet) StateLoad(m state.Source) {
	m.LoadValue(0, new(*FrameRefSegmentDataSlices), func(y interface{}) { x.loadRoot(y.(*FrameRefSegmentDataSlices)) })
}

func (x *FrameRefnode) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.FrameRefnode"
}

func (x *FrameRefnode) StateFields() []string {
	return []string{
		"nrSegments",
		"parent",
		"parentIndex",
		"hasChildren",
		"maxGap",
		"keys",
		"values",
		"children",
	}
}

func (x *FrameRefnode) beforeSave() {}

func (x *FrameRefnode) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.nrSegments)
	m.Save(1, &x.parent)
	m.Save(2, &x.parentIndex)
	m.Save(3, &x.hasChildren)
	m.Save(4, &x.maxGap)
	m.Save(5, &x.keys)
	m.Save(6, &x.values)
	m.Save(7, &x.children)
}

func (x *FrameRefnode) afterLoad() {}

func (x *FrameRefnode) StateLoad(m state.Source) {
	m.Load(0, &x.nrSegments)
	m.Load(1, &x.parent)
	m.Load(2, &x.parentIndex)
	m.Load(3, &x.hasChildren)
	m.Load(4, &x.maxGap)
	m.Load(5, &x.keys)
	m.Load(6, &x.values)
	m.Load(7, &x.children)
}

func (x *FrameRefSegmentDataSlices) StateTypeName() string {
	return "pkg/sentry/fs/fsutil.FrameRefSegmentDataSlices"
}

func (x *FrameRefSegmentDataSlices) StateFields() []string {
	return []string{
		"Start",
		"End",
		"Values",
	}
}

func (x *FrameRefSegmentDataSlices) beforeSave() {}

func (x *FrameRefSegmentDataSlices) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.Start)
	m.Save(1, &x.End)
	m.Save(2, &x.Values)
}

func (x *FrameRefSegmentDataSlices) afterLoad() {}

func (x *FrameRefSegmentDataSlices) StateLoad(m state.Source) {
	m.Load(0, &x.Start)
	m.Load(1, &x.End)
	m.Load(2, &x.Values)
}

func init() {
	state.Register((*DirtySet)(nil))
	state.Register((*Dirtynode)(nil))
	state.Register((*DirtySegmentDataSlices)(nil))
	state.Register((*FileRangeSet)(nil))
	state.Register((*FileRangenode)(nil))
	state.Register((*FileRangeSegmentDataSlices)(nil))
	state.Register((*FrameRefSet)(nil))
	state.Register((*FrameRefnode)(nil))
	state.Register((*FrameRefSegmentDataSlices)(nil))
}
