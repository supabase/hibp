package hibp

import (
	"bytes"
	"sync"
)

// bufferPool holds a pool of *bytes.Buffer used to read only valid responses
// from the HaveIBeenPwned.org API. Invalid responses (like a 503 error) do not
// use a buffer from here.
var bufferPool = &sync.Pool{
	New: func() any {
		// usual responses from HIBP are around 42kb
		return bytes.NewBuffer(make([]byte, 0, 42*1024))
	},
}

// suffixesPool holds a pool of [][]byte slices that hold parsed suffixes from
// the Pwned Passwords API.
var suffixesPool = &sync.Pool{
	New: func() any {
		// usually there are around 1000 suffixes per response
		buf := make([][]byte, 0, 1024)
		return &buf
	},
}
