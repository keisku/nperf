package intern

import (
	"runtime"
	"sync"
	"unsafe"
)

// A StringValue pointer is the handle to the underlying string value.
// See Get how Value pointers may be used.
type StringValue struct {
	_           [0]func() // prevent people from accidentally using value type as comparable
	cmpVal      string
	resurrected bool
}

// Get the underlying string value
func (v *StringValue) Get() string {
	if v == nil {
		return ""
	}
	return v.cmpVal
}

// StringInterner interns strings while allowing them to be cleaned up by the GC.
// It can handle both string and []byte types without allocation.
type StringInterner struct {
	mu     sync.Mutex
	valMap map[string]uintptr
}

// NewStringInterner creates a new StringInterner
func NewStringInterner() *StringInterner {
	return &StringInterner{
		valMap: make(map[string]uintptr),
	}
}

// GetString returns a pointer representing the string k
//
// The returned pointer will be the same for GetString(v) and GetString(v2)
// if and only if v == v2. The returned pointer will also be the same
// for a byte slice with same contents as the string.
//
//go:nocheckptr
func (s *StringInterner) GetString(k string) *StringValue {
	s.mu.Lock()
	defer s.mu.Unlock()

	var v *StringValue
	if addr, ok := s.valMap[k]; ok {
		//goland:noinspection GoVetUnsafePointer
		v = (*StringValue)((unsafe.Pointer)(addr))
		v.resurrected = true
		return v
	}

	v = &StringValue{cmpVal: k}
	runtime.SetFinalizer(v, s.finalize)
	s.valMap[k] = uintptr(unsafe.Pointer(v))
	return v
}

// Get returns a pointer representing the []byte k
//
// The returned pointer will be the same for Get(v) and Get(v2)
// if and only if v == v2. The returned pointer will also be the same
// for a string with same contents as the byte slice.
//
//go:nocheckptr
func (s *StringInterner) Get(k []byte) *StringValue {
	s.mu.Lock()
	defer s.mu.Unlock()

	var v *StringValue
	// the compiler will optimize the following map lookup to not alloc a string
	if addr, ok := s.valMap[string(k)]; ok {
		//goland:noinspection GoVetUnsafePointer
		v = (*StringValue)((unsafe.Pointer)(addr))
		v.resurrected = true
		return v
	}

	v = &StringValue{cmpVal: string(k)}
	runtime.SetFinalizer(v, s.finalize)
	s.valMap[string(k)] = uintptr(unsafe.Pointer(v))
	return v
}

func (s *StringInterner) finalize(v *StringValue) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if v.resurrected {
		// We lost the race. Somebody resurrected it while we
		// were about to finalize it. Try again next round.
		v.resurrected = false
		runtime.SetFinalizer(v, s.finalize)
		return
	}
	delete(s.valMap, v.Get())
}
