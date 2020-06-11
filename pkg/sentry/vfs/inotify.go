// Copyright 2020 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package vfs

import (
	"bytes"
	"fmt"
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/uniqueid"
	"gvisor.dev/gvisor/pkg/sync"
	"gvisor.dev/gvisor/pkg/syserror"
	"gvisor.dev/gvisor/pkg/usermem"
	"gvisor.dev/gvisor/pkg/waiter"
)

// inotifyEventBaseSize is the base size of linux's struct inotify_event. This
// must be a power 2 for rounding below.
const inotifyEventBaseSize = 16

// EventType defines different kinds of inotfiy events.
//
// The way events are labelled appears somewhat arbitrary, but they must match
// Linux so that IN_EXCL_UNLINK behaves as it does in Linux.
type EventType uint8

// PathEvent and InodeEvent correspond to FSNOTIFY_EVENT_PATH and
// FSNOTIFY_EVENT_INODE in Linux.
const (
	PathEvent  EventType = iota
	InodeEvent EventType = iota
)

// Inotify represents an inotify instance created by inotify_init(2) or
// inotify_init1(2). Inotify implements FileDescriptionImpl.
//
// Lock ordering:
//   Inotify.mu -> Watches.mu -> Inotify.evMu
//
// +stateify savable
type Inotify struct {
	vfsfd FileDescription
	FileDescriptionDefaultImpl
	DentryMetadataFileDescriptionImpl
	NoLockFD

	// Unique identifier for this inotify instance. We don't just reuse the
	// inotify fd because fds can be duped. These should not be exposed to the
	// user, since we may aggressively reuse an id on S/R.
	id uint64

	// queue is used to notify interested parties when the inotify instance
	// becomes readable or writable.
	queue waiter.Queue `state:"nosave"`

	// evMu *only* protects the events list. We need a separate lock while
	// queuing events: using mu may violate lock ordering, since at that point
	// the calling goroutine may already hold Watches.mu.
	evMu sync.Mutex `state:"nosave"`

	// A list of pending events for this inotify instance. Protected by evMu.
	events eventList

	// A scratch buffer, used to serialize inotify events. Allocate this
	// ahead of time for the sake of performance. Protected by evMu.
	scratch []byte

	// mu protects the fields below.
	mu sync.Mutex `state:"nosave"`

	// nextWatchMinusOne is used to allocate watch descriptors on this Inotify
	// instance. Note that Linux starts numbering watch descriptors from 1.
	nextWatchMinusOne int32

	// Map from watch descriptors to watch objects.
	watches map[int32]*Watch
}

var _ FileDescriptionImpl = (*Inotify)(nil)

// NewInotifyFD constructs a new Inotify instance.
func NewInotifyFD(ctx context.Context, vfsObj *VirtualFilesystem, flags uint32) (*FileDescription, error) {
	// O_CLOEXEC affects file descriptors, so it must be handled outside of vfs.
	flags &^= linux.O_CLOEXEC
	if flags&^linux.O_NONBLOCK != 0 {
		return nil, syserror.EINVAL
	}

	id := uniqueid.GlobalFromContext(ctx)
	vd := vfsObj.NewAnonVirtualDentry(fmt.Sprintf("[inotifyfd:%d]", id))
	defer vd.DecRef()
	fd := &Inotify{
		id:      id,
		scratch: make([]byte, inotifyEventBaseSize),
		watches: make(map[int32]*Watch),
	}
	if err := fd.vfsfd.Init(fd, flags, vd.Mount(), vd.Dentry(), &FileDescriptionOptions{
		UseDentryMetadata: true,
		DenyPRead:         true,
		DenyPWrite:        true,
	}); err != nil {
		return nil, err
	}
	return &fd.vfsfd, nil
}

// Release implements FileDescriptionImpl.Release. Release removes all
// watches and frees all resources for an inotify instance.
func (i *Inotify) Release() {
	// We need to hold i.mu to avoid a race with concurrent calls to
	// Inotify.handleDeletion from Watches. There's no risk of Watches
	// accessing this Inotify after the destructor ends, because we remove all
	// references to it below.
	i.mu.Lock()
	defer i.mu.Unlock()
	for _, w := range i.watches {
		// Remove references to the watch from the watches set on the target. We
		// don't need to worry about the references from i.watches, since this
		// file description is about to be destroyed.
		w.set.Remove(i.id)
	}
}

// EventRegister implements waiter.Waitable.
func (i *Inotify) EventRegister(e *waiter.Entry, mask waiter.EventMask) {
	i.queue.EventRegister(e, mask)
}

// EventUnregister implements waiter.Waitable.
func (i *Inotify) EventUnregister(e *waiter.Entry) {
	i.queue.EventUnregister(e)
}

// Readiness implements waiter.Waitable.Readiness.
//
// Readiness indicates whether there are pending events for an inotify instance.
func (i *Inotify) Readiness(mask waiter.EventMask) waiter.EventMask {
	ready := waiter.EventMask(0)

	i.evMu.Lock()
	defer i.evMu.Unlock()

	if !i.events.Empty() {
		ready |= waiter.EventIn
	}

	return mask & ready
}

// PRead implements FileDescriptionImpl.
func (*Inotify) PRead(ctx context.Context, dst usermem.IOSequence, offset int64, opts ReadOptions) (int64, error) {
	return 0, syserror.ESPIPE
}

// PWrite implements FileDescriptionImpl.
func (*Inotify) PWrite(ctx context.Context, src usermem.IOSequence, offset int64, opts WriteOptions) (int64, error) {
	return 0, syserror.ESPIPE
}

// Write implements FileDescriptionImpl.Write.
func (*Inotify) Write(ctx context.Context, src usermem.IOSequence, opts WriteOptions) (int64, error) {
	return 0, syserror.EBADF
}

// Read implements FileDescriptionImpl.Read.
func (i *Inotify) Read(ctx context.Context, dst usermem.IOSequence, opts ReadOptions) (int64, error) {
	if dst.NumBytes() < inotifyEventBaseSize {
		return 0, syserror.EINVAL
	}

	i.evMu.Lock()
	defer i.evMu.Unlock()

	if i.events.Empty() {
		// Nothing to read yet, tell caller to block.
		return 0, syserror.ErrWouldBlock
	}

	var writeLen int64
	for it := i.events.Front(); it != nil; {
		// Advance `it` before the element is removed from the list, or else
		// it.Next() will always be nil.
		event := it
		it = it.Next()

		// Does the buffer have enough remaining space to hold the event we're
		// about to write out?
		if dst.NumBytes() < int64(event.sizeOf()) {
			if writeLen > 0 {
				// Buffer wasn't big enough for all pending events, but we did
				// write some events out.
				return writeLen, nil
			}
			return 0, syserror.EINVAL
		}

		// Linux always dequeues an available event as long as there's enough
		// buffer space to copy it out, even if the copy below fails. Emulate
		// this behaviour.
		i.events.Remove(event)

		// Buffer has enough space, copy event to the read buffer.
		n, err := event.CopyTo(ctx, i.scratch, dst)
		if err != nil {
			return 0, err
		}

		writeLen += n
		dst = dst.DropFirst64(n)
	}
	return writeLen, nil
}

// Ioctl implements fs.FileOperations.Ioctl.
func (i *Inotify) Ioctl(ctx context.Context, uio usermem.IO, args arch.SyscallArguments) (uintptr, error) {
	switch args[1].Int() {
	case linux.FIONREAD:
		i.evMu.Lock()
		defer i.evMu.Unlock()
		var n uint32
		for e := i.events.Front(); e != nil; e = e.Next() {
			n += uint32(e.sizeOf())
		}
		var buf [4]byte
		usermem.ByteOrder.PutUint32(buf[:], n)
		_, err := uio.CopyOut(ctx, args[2].Pointer(), buf[:], usermem.IOOpts{})
		return 0, err

	default:
		return 0, syserror.ENOTTY
	}
}

func (i *Inotify) queueEvent(ev *Event) {
	i.evMu.Lock()

	// Check if we should coalesce the event we're about to queue with the last
	// one currently in the queue. Events are coalesced if they are identical.
	if last := i.events.Back(); last != nil {
		if ev.equals(last) {
			// "Coalesce" the two events by simply not queuing the new one. We
			// don't need to raise a waiter.EventIn notification because no new
			// data is available for reading.
			i.evMu.Unlock()
			return
		}
	}

	i.events.PushBack(ev)

	// Release mutex before notifying waiters because we don't control what they
	// can do.
	i.evMu.Unlock()

	i.queue.Notify(waiter.EventIn)
}

// newWatchLocked creates and adds a new watch to target.
//
// Precondition: i.mu must be locked.
func (i *Inotify) newWatchLocked(target *Dentry, mask uint32) *Watch {
	targetWatches := target.Watches()
	w := &Watch{
		owner: i,
		wd:    i.nextWatchIDLocked(),
		set:   targetWatches,
		mask:  mask,
	}

	// Hold the watch in this inotify instance as well as the watch set on the
	// target.
	i.watches[w.wd] = w
	targetWatches.Add(w)
	return w
}

// newWatchIDLocked allocates and returns a new watch descriptor.
//
// Precondition: i.mu must be locked.
func (i *Inotify) nextWatchIDLocked() int32 {
	i.nextWatchMinusOne++
	return i.nextWatchMinusOne
}

// handleDeletion handles the deletion of the target of watch w. It removes w
// from i.watches and a watch removal event is generated.
func (i *Inotify) handleDeletion(w *Watch) {
	i.mu.Lock()
	_, found := i.watches[w.wd]
	delete(i.watches, w.wd)
	i.mu.Unlock()

	if found {
		i.queueEvent(newEvent(w.wd, "", linux.IN_IGNORED, 0))
	}
}

// AddWatch constructs a new inotify watch and adds it to the target. It
// returns the watch descriptor returned by inotify_add_watch(2).
func (i *Inotify) AddWatch(target *Dentry, mask uint32) int32 {
	// Note: Locking this inotify instance protects the result returned by
	// Lookup() below. With the lock held, we know for sure the lookup result
	// won't become stale because it's impossible for *this* instance to
	// add/remove watches on target.
	i.mu.Lock()
	defer i.mu.Unlock()

	// Does the target already have a watch from this inotify instance?
	if existing := target.Watches().Lookup(i.id); existing != nil {
		newmask := mask
		if mask&linux.IN_MASK_ADD != 0 {
			// "Add (OR) events to watch mask for this pathname if it already
			// exists (instead of replacing mask)." -- inotify(7)
			newmask |= atomic.LoadUint32(&existing.mask)
		}
		atomic.StoreUint32(&existing.mask, newmask)
		return existing.wd
	}

	// No existing watch, create a new watch.
	w := i.newWatchLocked(target, mask)
	return w.wd
}

// RmWatch looks up an inotify watch for the given 'wd' and configures the
// target to stop sending events to this inotify instance.
func (i *Inotify) RmWatch(wd int32) error {
	i.mu.Lock()

	// Find the watch we were asked to removed.
	w, ok := i.watches[wd]
	if !ok {
		i.mu.Unlock()
		return syserror.EINVAL
	}

	// Remove the watch from this instance.
	delete(i.watches, wd)

	// Remove the watch from the watch target.
	w.set.Remove(w.OwnerID())
	i.mu.Unlock()

	// Generate the event for the removal.
	i.queueEvent(newEvent(wd, "", linux.IN_IGNORED, 0))

	return nil
}

// Watches is the collection of all inotify watches on a single file.
//
// +stateify savable
type Watches struct {
	// mu protects the fields below.
	mu sync.RWMutex `state:"nosave"`

	// ws is the map of active watches in this collection, keyed by the inotify
	// instance id of the owner.
	ws map[uint64]*Watch
}

// Lookup returns the watch owned by an inotify instance with the given id.
// Returns nil if no such watch exists.
//
// Precondition: the inotify instance with the given id must be locked to
// prevent the returned watch from being concurrently modified or replaced in
// Inotify.watches.
func (w *Watches) Lookup(id uint64) *Watch {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.ws[id]
}

// Add adds watch into this set of watches.
//
// Precondition: the inotify instance with the given id must be locked.
func (w *Watches) Add(watch *Watch) {
	w.mu.Lock()
	defer w.mu.Unlock()

	owner := watch.OwnerID()
	// Sanity check, we should never have two watches for one owner on the
	// same target.
	if _, exists := w.ws[owner]; exists {
		panic(fmt.Sprintf("Watch collision with ID %+v", owner))
	}
	if w.ws == nil {
		w.ws = make(map[uint64]*Watch)
	}
	w.ws[owner] = watch
}

// Remove removes a watch with the given id from this set of watches and
// releases it. The caller is responsible for generating any watch removal
// event, as appropriate. The provided id must match an existing watch in this
// collection.
//
// Precondition: the inotify instance with the given id must be locked.
func (w *Watches) Remove(id uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.ws == nil {
		// This watch set is being destroyed. The thread executing the
		// destructor is already in the process of deleting all our watches. We
		// got here with no references on the target because we raced with the
		// destructor notifying all the watch owners of destruction. See the
		// comment in Watches.HandleDeletion for why this race exists.
		return
	}

	if _, ok := w.ws[id]; !ok {
		// While there's technically no problem with silently ignoring a missing
		// watch, this is almost certainly a bug.
		panic(fmt.Sprintf("Attempt to remove a watch, but no watch found with provided id %+v.", id))
	}
	delete(w.ws, id)
}

// Notify queues a new event with all watches in this set.
func (w *Watches) Notify(name string, events, cookie uint32, et EventType) {
	w.NotifyWithExclusions(name, events, cookie, et, false)
}

// NotifyWithExclusions queues a new event with watches in this set. Watches
// with IN_EXCL_UNLINK are skipped if the event is coming from a child that
// has been unlinked.
func (w *Watches) NotifyWithExclusions(name string, events, cookie uint32, et EventType, unlinked bool) {
	// N.B. We don't defer the unlocks because Notify is in the hot path of
	// all IO operations, and the defer costs too much for small IO
	// operations.
	w.mu.RLock()
	for _, watch := range w.ws {
		if unlinked && watch.ExcludeUnlinkedChildren() && et == PathEvent {
			continue
		}
		watch.Notify(name, events, cookie)
	}
	w.mu.RUnlock()
}

// HandleDeletion is called when the watch target is destroyed to emit
// the appropriate events.
func (w *Watches) HandleDeletion() {
	w.Notify("", linux.IN_DELETE_SELF, 0, InodeEvent)

	// TODO(gvisor.dev/issue/1479): This doesn't work because maps are not copied
	// by value. Ideally, we wouldn't have this circular locking so we can just
	// notify of IN_DELETE_SELF in the same loop below.
	//
	// We can't hold w.mu while calling watch.handleDeletion to preserve lock
	// ordering w.r.t to the owner inotify instances. Instead, atomically move
	// the watches map into a local variable so we can iterate over it safely.
	//
	// Because of this however, it is possible for the watches' owners to reach
	// this inode while the inode has no refs. This is still safe because the
	// owners can only reach the inode until this function finishes calling
	// watch.handleDeletion below and the inode is guaranteed to exist in the
	// meantime. But we still have to be very careful not to rely on inode state
	// that may have been already destroyed.
	var ws map[uint64]*Watch
	w.mu.Lock()
	ws = w.ws
	w.ws = nil
	w.mu.Unlock()

	for _, watch := range ws {
		// TODO(gvisor.dev/issue/1479): consider refactoring this.
		watch.handleDeletion()
	}
}

// Watch represent a particular inotify watch created by inotify_add_watch.
//
// +stateify savable
type Watch struct {
	// Inotify instance which owns this watch.
	owner *Inotify

	// Descriptor for this watch. This is unique across an inotify instance.
	wd int32

	// set is the watch set containing this watch. It belongs to the target file
	// of this watch.
	set *Watches

	// Events being monitored via this watch. Must be accessed with atomic
	// memory operations.
	mask uint32
}

// OwnerID returns the id of the inotify instance that owns this watch.
func (w *Watch) OwnerID() uint64 {
	return w.owner.id
}

// ExcludeUnlinkedChildren indicates whether the watched object should continue
// to be notified of events of its children after they have been unlinked, e.g.
// for an open file descriptor.
//
// TODO(gvisor.dev/issue/1479): Implement IN_EXCL_UNLINK.
// We can do this by keeping track of the set of unlinked children in Watches
// to skip notification.
func (w *Watch) ExcludeUnlinkedChildren() bool {
	return atomic.LoadUint32(&w.mask)&linux.IN_EXCL_UNLINK != 0
}

// Notify queues a new event on this watch.
func (w *Watch) Notify(name string, events uint32, cookie uint32) {
	mask := atomic.LoadUint32(&w.mask)
	if mask&events == 0 {
		// We weren't watching for this event.
		return
	}

	// Event mask should include bits matched from the watch plus all control
	// event bits.
	unmaskableBits := ^uint32(0) &^ linux.IN_ALL_EVENTS
	effectiveMask := unmaskableBits | mask
	matchedEvents := effectiveMask & events
	w.owner.queueEvent(newEvent(w.wd, name, matchedEvents, cookie))
}

// handleDeletion handles the deletion of w's target.
func (w *Watch) handleDeletion() {
	w.owner.handleDeletion(w)
}

// Event represents a struct inotify_event from linux.
//
// +stateify savable
type Event struct {
	eventEntry

	wd     int32
	mask   uint32
	cookie uint32

	// len is computed based on the name field is set automatically by
	// Event.setName. It should be 0 when no name is set; otherwise it is the
	// length of the name slice.
	len uint32

	// The name field has special padding requirements and should only be set by
	// calling Event.setName.
	name []byte
}

func newEvent(wd int32, name string, events, cookie uint32) *Event {
	e := &Event{
		wd:     wd,
		mask:   events,
		cookie: cookie,
	}
	if name != "" {
		e.setName(name)
	}
	return e
}

// paddedBytes converts a go string to a null-terminated c-string, padded with
// null bytes to a total size of 'l'. 'l' must be large enough for all the bytes
// in the 's' plus at least one null byte.
func paddedBytes(s string, l uint32) []byte {
	if l < uint32(len(s)+1) {
		panic("Converting string to byte array results in truncation, this can lead to buffer-overflow due to the missing null-byte!")
	}
	b := make([]byte, l)
	copy(b, s)

	// b was zero-value initialized during make(), so the rest of the slice is
	// already filled with null bytes.

	return b
}

// setName sets the optional name for this event.
func (e *Event) setName(name string) {
	// We need to pad the name such that the entire event length ends up a
	// multiple of inotifyEventBaseSize.
	unpaddedLen := len(name) + 1
	// Round up to nearest multiple of inotifyEventBaseSize.
	e.len = uint32((unpaddedLen + inotifyEventBaseSize - 1) & ^(inotifyEventBaseSize - 1))
	// Make sure we haven't overflowed and wrapped around when rounding.
	if unpaddedLen > int(e.len) {
		panic("Overflow when rounding inotify event size, the 'name' field was too big.")
	}
	e.name = paddedBytes(name, e.len)
}

func (e *Event) sizeOf() int {
	s := inotifyEventBaseSize + int(e.len)
	if s < inotifyEventBaseSize {
		panic("overflow")
	}
	return s
}

// CopyTo serializes this event to dst. buf is used as a scratch buffer to
// construct the output. We use a buffer allocated ahead of time for
// performance. buf must be at least inotifyEventBaseSize bytes.
func (e *Event) CopyTo(ctx context.Context, buf []byte, dst usermem.IOSequence) (int64, error) {
	usermem.ByteOrder.PutUint32(buf[0:], uint32(e.wd))
	usermem.ByteOrder.PutUint32(buf[4:], e.mask)
	usermem.ByteOrder.PutUint32(buf[8:], e.cookie)
	usermem.ByteOrder.PutUint32(buf[12:], e.len)

	writeLen := 0

	n, err := dst.CopyOut(ctx, buf)
	if err != nil {
		return 0, err
	}
	writeLen += n
	dst = dst.DropFirst(n)

	if e.len > 0 {
		n, err = dst.CopyOut(ctx, e.name)
		if err != nil {
			return 0, err
		}
		writeLen += n
	}

	// Santiy check.
	if writeLen != e.sizeOf() {
		panic(fmt.Sprintf("Serialized unexpected amount of data for an event, expected %d, wrote %d.", e.sizeOf(), writeLen))
	}

	return int64(writeLen), nil
}

func (e *Event) equals(other *Event) bool {
	return e.wd == other.wd &&
		e.mask == other.mask &&
		e.cookie == other.cookie &&
		e.len == other.len &&
		bytes.Equal(e.name, other.name)
}

// InotifyEventFromStatMask generates the appropriate events for an operation
// that set the stats specified in mask.
func InotifyEventFromStatMask(mask uint32) uint32 {
	var ev uint32
	if mask&(linux.STATX_UID|linux.STATX_GID|linux.STATX_MODE) != 0 {
		ev |= linux.IN_ATTRIB
	}
	if mask&linux.STATX_SIZE != 0 {
		ev |= linux.IN_MODIFY
	}

	if (mask & (linux.STATX_ATIME | linux.STATX_MTIME)) == (linux.STATX_ATIME | linux.STATX_MTIME) {
		// Both times indicates a utime(s) call.
		ev |= linux.IN_ATTRIB
	} else if mask&linux.STATX_ATIME != 0 {
		ev |= linux.IN_ACCESS
	} else if mask&linux.STATX_MTIME != 0 {
		mask |= linux.IN_MODIFY
	}
	return ev
}

// InotifyRemoveChild sends the appriopriate notifications to the watch sets of
// the child being removed and its parent.
func InotifyRemoveChild(self, parent *Watches, name string) {
	self.Notify("", linux.IN_ATTRIB, 0, InodeEvent)
	parent.Notify(name, linux.IN_DELETE, 0, InodeEvent)
	// TODO(gvisor.dev/issue/1479): implement IN_EXCL_UNLINK.
}

// InotifyRename sends the appriopriate notifications to the watch sets of the
// file being renamed and its old/new parents.
func InotifyRename(ctx context.Context, renamed, oldParent, newParent *Watches, oldName, newName string, isDir bool) {
	var dirEv uint32
	if isDir {
		dirEv = linux.IN_ISDIR
	}
	cookie := uniqueid.InotifyCookie(ctx)
	oldParent.Notify(oldName, dirEv|linux.IN_MOVED_FROM, cookie, InodeEvent)
	newParent.Notify(newName, dirEv|linux.IN_MOVED_TO, cookie, InodeEvent)
	// Somewhat surprisingly, self move events do not have a cookie.
	renamed.Notify("", linux.IN_MOVE_SELF, 0, InodeEvent)
}