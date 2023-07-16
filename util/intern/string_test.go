package intern

import (
	"fmt"
	"runtime"
	"testing"
)

func TestBasics(t *testing.T) {
	si := NewStringInterner()
	foo := si.GetString("foo")
	empty := si.GetString("")
	fooBytes := si.Get([]byte{'f', 'o', 'o'})
	foo2 := si.GetString("foo")
	empty2 := si.GetString("")
	foo2Bytes := si.Get([]byte{'f', 'o', 'o'})

	if foo.Get() != foo2.Get() {
		t.Error("foo/foo2 values differ")
	}
	if fooBytes.Get() != foo2Bytes.Get() {
		t.Error("foo/foo2 values differ")
	}
	if empty.Get() != empty2.Get() {
		t.Error("empty/empty2 values differ")
	}
	if foo.Get() != fooBytes.Get() {
		t.Error("foo/foobytes values differ")
	}

	if n := si.mapLen(); n != 2 {
		t.Errorf("map len = %d; want 2", n)
	}

	wantEmpty(t, si)
}

var (
	globalString = "not a constant"
	globalBytes  = []byte{'n', 'o', 't', 'c', 'o', 'n', 's', 't', 'a', 'n', 't'}
)

func TestGetAllocs(t *testing.T) {
	si := NewStringInterner()
	allocs := int(testing.AllocsPerRun(100, func() {
		si.Get(globalBytes)
	}))
	if allocs != 0 {
		t.Errorf("Get allocated %d objects, want 0", allocs)
	}
}

func TestGetStringAllocs(t *testing.T) {
	si := NewStringInterner()
	allocs := int(testing.AllocsPerRun(100, func() {
		si.GetString(globalString)
	}))
	if allocs != 0 {
		t.Errorf("GetString allocated %d objects, want 0", allocs)
	}
}

func (s *StringInterner) mapLen() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.valMap)
}

func (s *StringInterner) mapKeys() (keys []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.valMap {
		keys = append(keys, fmt.Sprint(k))
	}
	return keys
}

func wantEmpty(t testing.TB, s *StringInterner) {
	t.Helper()
	const gcTries = 5000
	for try := 0; try < gcTries; try++ {
		runtime.GC()
		n := s.mapLen()
		if n == 0 {
			break
		}
		if try == gcTries-1 {
			t.Errorf("map len = %d after (%d GC tries); want 0, contents: %v", n, gcTries, s.mapKeys())
		}
	}
}
