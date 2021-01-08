// automatically generated by stateify.

package usermem

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (a *AccessType) StateTypeName() string {
	return "pkg/usermem.AccessType"
}

func (a *AccessType) StateFields() []string {
	return []string{
		"Read",
		"Write",
		"Execute",
	}
}

func (a *AccessType) beforeSave() {}

func (a *AccessType) StateSave(stateSinkObject state.Sink) {
	a.beforeSave()
	stateSinkObject.Save(0, &a.Read)
	stateSinkObject.Save(1, &a.Write)
	stateSinkObject.Save(2, &a.Execute)
}

func (a *AccessType) afterLoad() {}

func (a *AccessType) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &a.Read)
	stateSourceObject.Load(1, &a.Write)
	stateSourceObject.Load(2, &a.Execute)
}

func (v *Addr) StateTypeName() string {
	return "pkg/usermem.Addr"
}

func (v *Addr) StateFields() []string {
	return nil
}

func (r *AddrRange) StateTypeName() string {
	return "pkg/usermem.AddrRange"
}

func (r *AddrRange) StateFields() []string {
	return []string{
		"Start",
		"End",
	}
}

func (r *AddrRange) beforeSave() {}

func (r *AddrRange) StateSave(stateSinkObject state.Sink) {
	r.beforeSave()
	stateSinkObject.Save(0, &r.Start)
	stateSinkObject.Save(1, &r.End)
}

func (r *AddrRange) afterLoad() {}

func (r *AddrRange) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &r.Start)
	stateSourceObject.Load(1, &r.End)
}

func init() {
	state.Register((*AccessType)(nil))
	state.Register((*Addr)(nil))
	state.Register((*AddrRange)(nil))
}
