package hibp

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPwnedResultParsing(t *testing.T) {
	examples := []struct {
		Example  string
		Suffixes [][]byte
		Sorted   bool
	}{
		{
			Example:  ``,
			Suffixes: nil,
			Sorted:   true,
		},
		{
			Example:  "invalid example\n",
			Suffixes: nil,
			Sorted:   true,
		},
		{
			Example: "0123456789ABCDEF0123456789ABCDEF012:1\n",
			Suffixes: [][]byte{
				[]byte("0123456789ABCDEF0123456789ABCDEF012"),
			},
			Sorted: true,
		},
		{
			// result does not end with a newline character
			Example: "0123456789ABCDEF0123456789ABCDEF012:1",
			Suffixes: [][]byte{
				[]byte("0123456789ABCDEF0123456789ABCDEF012"),
			},
			Sorted: true,
		},
		{
			Example: "0123456789ABCDEF0123456789ABCDEF012:1\n1123456789ABCDEF0123456789ABCDEF012:1\n",
			Suffixes: [][]byte{
				[]byte("0123456789ABCDEF0123456789ABCDEF012"),
				[]byte("1123456789ABCDEF0123456789ABCDEF012"),
			},
			Sorted: true,
		},
		{
			Example: "1123456789ABCDEF0123456789ABCDEF012:1\n0123456789ABCDEF0123456789ABCDEF012:1\n",
			Suffixes: [][]byte{
				[]byte("1123456789ABCDEF0123456789ABCDEF012"),
				[]byte("0123456789ABCDEF0123456789ABCDEF012"),
			},
			Sorted: false,
		},
		{
			// padding line (0 ocurrences of the prefix)
			Example:  "0123456789ABCDEF0123456789ABCDEF012:0\n",
			Suffixes: nil,
			Sorted:   true,
		},
	}

	for i, example := range examples {
		buf := &pwnedResultBuffer{
			Buffer: bytes.NewBuffer(nil),
		}

		buf.Buffer.WriteString(example.Example)

		buf.Parse()

		if buf.SuffixesSorted != example.Sorted {
			t.Errorf("Unexpected sorting for example %d", i)
		}

		if len(buf.Suffixes) != len(example.Suffixes) {
			t.Errorf("Unexpected suffixes for example %d, %d != %d", i, len(example.Suffixes), len(buf.Suffixes))
		} else {
			for j, suffix := range example.Suffixes {
				if !bytes.Equal(suffix, buf.Suffixes[j]) {
					t.Errorf("Unexpected suffix for example %d at position %d, %q != %q", i, j, suffix, buf.Suffixes[j])
				}
			}
		}

		for _, suffix := range buf.Suffixes {
			if !buf.Lookup(suffix) {
				t.Errorf("Expected to find suffix %q but didn't in example %d", suffix, i)
			}
		}

		if buf.Lookup([]byte("cantexist")) {
			t.Errorf("Found suffix that can't exist")
		}

		_, err := buf.Read(nil)
		if err != nil {
			t.Errorf("Unexpected error %v", err)
		}

		err = buf.Close()
		if err != nil {
			t.Errorf("Unexpected error %v", err)
		}
	}
}

type testHTTPClient struct {
	Fn func(*http.Request) (*http.Response, error)
}

func (c *testHTTPClient) Do(r *http.Request) (*http.Response, error) {
	return c.Fn(r)
}

func TestSingleRequestForSamePrefix(t *testing.T) {
	called := int32(0)

	pwnedClient := PwnedClient{
		HTTP: &testHTTPClient{
			Fn: func(r *http.Request) (*http.Response, error) {
				atomic.AddInt32(&called, 1)

				time.Sleep(10 * time.Millisecond)

				return nil, context.Canceled
			},
		},
	}

	wg := &sync.WaitGroup{}
	wg.Add(2)

	for i := 0; i < 2; i += 1 {
		go func() {
			defer wg.Done()

			_, err := pwnedClient.Check(context.Background(), "password1")
			if !errors.Is(err, context.Canceled) {
				t.Errorf("Unexpected error %v", err)
			}
		}()
	}

	wg.Wait()

	if called != 1 {
		t.Errorf("Expected a single HTTP call, but got %v", called)
	}
}

type testErrorReader struct {
	Error error
}

func (r *testErrorReader) Read(into []byte) (int, error) {
	return 0, r.Error
}

func (r *testErrorReader) Close() error {
	return nil
}

func TestFailingBodyRead(t *testing.T) {
	pwnedClient := PwnedClient{
		HTTP: &testHTTPClient{
			Fn: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Request:    r,
					Body: &testErrorReader{
						Error: context.Canceled,
					},
				}, nil
			},
		},
	}

	res, err := pwnedClient.Check(context.Background(), "password1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Unexpected error %v", err)
	}

	if res {
		t.Errorf("Expected result to be false but was true")
	}
}

func TestNilContextToDoRequest(t *testing.T) {
	pwnedClient := PwnedClient{
		HTTP: &testHTTPClient{
			Fn: func(r *http.Request) (*http.Response, error) {
				return nil, context.Canceled
			},
		},
	}

	//lint:ignore SA1012 intentionally passing a nil Context below to
	// trigger the error return from http.NewRequestWithContext internally
	_, err := pwnedClient.doRequest(nil, &pwnedResultBuffer{}, []byte("ABCDE"))
	if err.Error() != "net/http: nil Context" {
		t.Errorf("Unexpected error %v", err)
	}
}

type testPwnedCache struct {
	AddFn      func(context.Context, []byte, [][]byte) error
	ContainsFn func(context.Context, []byte, []byte) (bool, error)
}

func (c *testPwnedCache) Add(ctx context.Context, prefix []byte, suffixes [][]byte) error {
	return c.AddFn(ctx, prefix, suffixes)
}

func (c *testPwnedCache) Contains(ctx context.Context, prefix []byte, suffix []byte) (bool, error) {
	return c.ContainsFn(ctx, prefix, suffix)
}

func TestCheckWithNilContext(t *testing.T) {
	pwnedClient := PwnedClient{
		HTTP: &testHTTPClient{
			Fn: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Request:    r,
					Body:       io.NopCloser(bytes.NewReader([]byte("214943DAAD1D64C102FAEC29DE4AFE9DA3D:1\r\n"))),
				}, nil
			},
		},
	}

	//lint:ignore SA1012 intentionally passing nil Context to check that
	// the function will use context.Background() properly
	_, err := pwnedClient.Check(nil, "password1")
	if err != nil {
		t.Errorf("Unexpected error %v", err)
		return
	}
}

func TestPwnedCache(t *testing.T) {
	addCalls := 0
	containsCalls := 0
	httpCalls := 0

	var prefix []byte
	var suffixes [][]byte

	pwnedClient := PwnedClient{
		Cache: &testPwnedCache{
			AddFn: func(ctx context.Context, addPrefix []byte, addSuffixes [][]byte) error {
				addCalls += 1

				prefix = make([]byte, len(addPrefix))
				copy(prefix, addPrefix)

				suffixes = make([][]byte, len(addSuffixes))
				for i := range addSuffixes {
					suffixes[i] = make([]byte, len(addSuffixes[i]))
					copy(suffixes[i], addSuffixes[i])
				}

				return nil
			},
			ContainsFn: func(ctx context.Context, containsPrefix, containsSuffix []byte) (bool, error) {
				containsCalls += 1

				if !bytes.Equal(containsPrefix, prefix) {
					return false, nil
				}

				for _, suffix := range suffixes {
					if bytes.Equal(containsSuffix, suffix) {
						return true, nil
					}
				}

				return false, nil
			},
		},
		HTTP: &testHTTPClient{
			Fn: func(r *http.Request) (*http.Response, error) {
				httpCalls += 1

				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Request:    r,
					Body:       io.NopCloser(bytes.NewReader([]byte("214943DAAD1D64C102FAEC29DE4AFE9DA3D:1\r\n"))),
				}, nil
			},
		},
	}

	res, err := pwnedClient.Check(context.Background(), "password1")
	if err != nil {
		t.Errorf("Unexpected error %v", err)
		return
	}

	if !res {
		t.Error("Expected to find the password, but didn't")
	}

	if addCalls != 1 {
		t.Errorf("Add was called %d times, but was supposed to be called once", addCalls)
	}

	if containsCalls != 1 {
		t.Errorf("Contains was called %d times, but was supposed to be called once", containsCalls)
	}

	if httpCalls != 1 {
		t.Errorf("HTTP API was called %d times, but was supposed to be called once", httpCalls)
	}

	res, err = pwnedClient.Check(context.Background(), "password1")
	if err != nil {
		t.Errorf("Unexpected error %v", err)
		return
	}

	if !res {
		t.Error("Expected to find the password, but didn't")
	}

	if addCalls != 1 {
		t.Errorf("Add was called %d times, but was supposed to be called once", addCalls)
	}

	if containsCalls != 2 {
		t.Errorf("Contains was called %d times, but was supposed to be called twice", containsCalls)
	}

	if httpCalls != 1 {
		t.Errorf("HTTP API was called %d times, but was supposed to be called once", httpCalls)
	}
}

func TestPwnedCacheWithError(t *testing.T) {
	containsCalls := 0

	pwnedClient := PwnedClient{
		Cache: &testPwnedCache{
			AddFn: func(ctx context.Context, addPrefix []byte, addSuffixes [][]byte) error {
				return context.Canceled
			},
			ContainsFn: func(ctx context.Context, containsPrefix, containsSuffix []byte) (bool, error) {
				containsCalls += 1

				if containsCalls > 1 {
					return false, context.Canceled
				}

				return false, nil
			},
		},
		HTTP: &testHTTPClient{
			Fn: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Status:     "200 OK",
					Request:    r,
					Body:       io.NopCloser(bytes.NewReader([]byte("214943DAAD1D64C102FAEC29DE4AFE9DA3D:1\r\n"))),
				}, nil
			},
		},
	}

	_, err := pwnedClient.Check(context.Background(), "password1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Unexpected error %v", err)
		return
	}

	_, err = pwnedClient.Check(context.Background(), "password1")
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Unexpected error %v", err)
		return
	}
}

func TestUserAgent(t *testing.T) {
	var userAgent string

	pwnedClient := PwnedClient{
		UserAgent: "test",
		HTTP: &testHTTPClient{
			Fn: func(r *http.Request) (*http.Response, error) {
				userAgent = r.UserAgent()

				return nil, context.Canceled
			},
		},
	}

	_, err := pwnedClient.Check(context.Background(), "password1")
	if err != nil && !errors.Is(err, context.Canceled) {
		t.Errorf("Unexpected error %v", err)
	}

	if userAgent != "test" {
		t.Errorf("Unexpected User-Agent %q", userAgent)
	}
}

func TestErrorUnexpectedResponse(t *testing.T) {
	pwnedClient := PwnedClient{
		HTTP: &testHTTPClient{
			Fn: func(r *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusBadRequest,
					Status:     "400 Bad Request",
					Body:       io.NopCloser(bytes.NewReader([]byte("Bad Request\n"))),
					Request:    r,
				}, nil
			},
		},
	}

	res, err := pwnedClient.Check(context.Background(), "password1")
	if err == nil {
		t.Errorf("Expected error, but got success")
		return
	}

	if res {
		t.Errorf("Expected false result, got true")
	}

	eur, ok := err.(*ErrorUnexpectedResponse)
	if !ok {
		t.Errorf("Expected ErrorUnexpectedResponse, got %t", err)
	}

	if eur.Response == nil {
		t.Errorf("No response present on the ErrorUnexpectedResponse object")
	}

	expectedError := "hibp: Unexpected HTTP Response \"400 Bad Request\" from GET \"https://api.pwnedpasswords.com/range/E38AD\""

	if eur.Error() != expectedError {
		t.Errorf("Unexpected error string %q expected %q", eur.Error(), expectedError)
	}
}

func TestEndToEnd(t *testing.T) {
	pwnedClient := PwnedClient{
		UserAgent: "tests for https://github.com/supabase/hibp",
	}

	res, err := pwnedClient.Check(context.Background(), "password1")
	if err != nil {
		eur, ok := err.(*ErrorUnexpectedResponse)
		if ok {
			if eur.Response.StatusCode >= 500 {
				t.Logf("Service temporarily unavailable %q", eur.Response.Status)
			} else {
				t.Errorf("Unexpected response %q", eur.Response.Status)
			}
		} else {
			t.Errorf("Unexpected error %v", err)
		}

		return
	}

	if !res {
		t.Errorf("Expected result to be true, but was false")
	}
}
