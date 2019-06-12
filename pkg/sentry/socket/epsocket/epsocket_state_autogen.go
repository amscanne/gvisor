// automatically generated by stateify.

package epsocket

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *SocketOperations) beforeSave() {}
func (x *SocketOperations) save(m state.Map) {
	x.beforeSave()
	m.Save("SendReceiveTimeout", &x.SendReceiveTimeout)
	m.Save("Queue", &x.Queue)
	m.Save("family", &x.family)
	m.Save("Endpoint", &x.Endpoint)
	m.Save("skType", &x.skType)
	m.Save("protocol", &x.protocol)
	m.Save("readView", &x.readView)
	m.Save("readCM", &x.readCM)
	m.Save("sender", &x.sender)
	m.Save("sockOptTimestamp", &x.sockOptTimestamp)
	m.Save("timestampValid", &x.timestampValid)
	m.Save("timestampNS", &x.timestampNS)
}

func (x *SocketOperations) afterLoad() {}
func (x *SocketOperations) load(m state.Map) {
	m.Load("SendReceiveTimeout", &x.SendReceiveTimeout)
	m.Load("Queue", &x.Queue)
	m.Load("family", &x.family)
	m.Load("Endpoint", &x.Endpoint)
	m.Load("skType", &x.skType)
	m.Load("protocol", &x.protocol)
	m.Load("readView", &x.readView)
	m.Load("readCM", &x.readCM)
	m.Load("sender", &x.sender)
	m.Load("sockOptTimestamp", &x.sockOptTimestamp)
	m.Load("timestampValid", &x.timestampValid)
	m.Load("timestampNS", &x.timestampNS)
}

func (x *Stack) beforeSave() {}
func (x *Stack) save(m state.Map) {
	x.beforeSave()
}

func (x *Stack) load(m state.Map) {
	m.AfterLoad(x.afterLoad)
}

func init() {
	state.Register("epsocket.SocketOperations", (*SocketOperations)(nil), state.Fns{Save: (*SocketOperations).save, Load: (*SocketOperations).load})
	state.Register("epsocket.Stack", (*Stack)(nil), state.Fns{Save: (*Stack).save, Load: (*Stack).load})
}
