package hibp

import (
	"testing"
)

func TestRefcountBoxRelease(t *testing.T) {
	releaseCalled := false

	box := refcountBox[any]{
		OnRelease: func() {
			releaseCalled = true
		},
	}

	box.Acquire()
	box.Release()

	if !releaseCalled {
		t.Error("OnRelease was not called")
	}
}
