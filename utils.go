package hibp

import (
	"sync/atomic"
)

// refcountBox maintains a reference count. When the reference count drops to
// 0, OnRelease is called.
type refcountBox[T any] struct {
	// Refcount is the current reference count.
	Refcount int32

	// OnRelease is a function called when reference count drops to 0.
	OnRelease func()

	// Value is the boxed value.
	Value T
}

// Acquire increases the reference count by 1.
func (b *refcountBox[T]) Acquire() {
	atomic.AddInt32(&b.Refcount, 1)
}

// Release decreases the reference count by 1 and calls OnRelease when it drops
// to 0.
func (b *refcountBox[T]) Release() {
	if atomic.AddInt32(&b.Refcount, -1) == 0 {
		b.OnRelease()
		b.OnRelease = nil
	}
}
