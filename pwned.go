package hibp

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// PwnedPasswordsURL returns the URL for the prefix.
func PwnedPasswordsURL(prefix string) string {
	return "https://api.pwnedpasswords.com/range/" + prefix
}

// DefaultUserAgent is the User-Agent header sent to the Pwned Passwords API if
// it has not been explicitly set.
var DefaultUserAgent = "https://github.com/supabase/hibp"

// PwnedCache is the interface with which you can cache responses from the
// Pwned Passwords API.
type PwnedCache interface {
	// Add records the provided prefix and suffixes in the cache.
	Add(ctx context.Context, prefix []byte, suffixes [][]byte) error

	// Contains checks if the provided prefix and suffix are in the cache.
	Contains(ctx context.Context, prefix, suffix []byte) (bool, error)
}

// PwnedClient can be used to send requests to the Pwned Passwords API. Zero
// value is safe to use, though it is highly recommended you configure the
// UserAgent property per the HaveIBeenPwned.org API rules.
type PwnedClient struct {
	// UserAgent is sent as the User-Agent header to HTTP requests.
	UserAgent string

	// Cache, when set, will be used to cache and lookup results.
	Cache PwnedCache

	// HTTP allows you to override the HTTP client used. If not set http.DefaultClient is used.
	HTTP interface {
		Do(*http.Request) (*http.Response, error)
	}

	// lock is used to synchronize access when needed.
	lock sync.Mutex

	// requests holds a map of prefixes. Before a password is checked, this
	// map is consulted to see if there's already an in-flight request for
	// the prefix. If it is, the refcount box is reused.
	requests map[string]*refcountBox[func() (*http.Response, error)]
}

// pwnedResultBuffer is used on res.Body to hold the original response body
// from the Pwned Passwords API as well as the parsed suffixes.
type pwnedResultBuffer struct {
	Buffer         *bytes.Buffer
	SuffixesSorted bool
	Suffixes       [][]byte
}

func (b *pwnedResultBuffer) Read(into []byte) (int, error) {
	return b.Buffer.Read(into)
}

func (b *pwnedResultBuffer) Close() error {
	// do nothing
	return nil
}

// pwnedLinePattern encodes the regular expression for parsing lines returned
// from the Pwned Passwords API. Excerpt:
//
// > When a password hash with the same first 5 characters is found in the Pwned
// > Passwords repository, the API will respond with an HTTP 200 and include the
// > suffix of every hash beginning with the specified prefix, followed by a
// > count of how many times it appears in the data set. The API consumer can
// > then search the results of the response for the presence of their source
// > hash and if not found, the password does not exist in the data set. A
// > sample SHA-1 response for the hash prefix "21BD1" would be as follows:
// >
// > ```
// > 0018A45C4D1DEF81644B54AB7F969B88D65:1
// > 00D4F6E8FA6EECAD2A3AA415EEC418D38EC:2
// > 011053FD0102E94D6AE2F8B83D76FAF94F6:1
// > 012A7CA357541F0AC487871FEEC1891C49C:2
// > 0136E006E24E7D152139815FB0FC6A50B15:2
// > ...
// > ```
var pwnedLinePattern = regexp.MustCompile(`^([0-9A-F]{35}):([0-9]+)\s*$`)

// Parse parses the password suffixes from the buffer.
func (buf *pwnedResultBuffer) Parse() {
	defer buf.Buffer.Reset()

	buf.SuffixesSorted = true

	running := true

	for running {
		line, err := buf.Buffer.ReadBytes('\n')
		if err != nil {
			// err can only be io.EOF here, Buffer does not return
			// any other errors
			running = false
		}

		matches := pwnedLinePattern.FindSubmatch(line)
		if matches == nil {
			continue
		}

		suffix := matches[1]
		occurrence := matches[2]

		if buf.SuffixesSorted && len(buf.Suffixes) > 0 {
			if bytes.Compare(buf.Suffixes[len(buf.Suffixes)-1], suffix) >= 0 {
				buf.SuffixesSorted = false
			}
		}

		if len(occurrence) > 1 || (len(occurrence) == 1 && occurrence[0] != '0') {
			buf.Suffixes = append(buf.Suffixes, suffix)
		}
	}
}

// Lookup searches through the parsed suffixes.
func (buf *pwnedResultBuffer) Lookup(suffix []byte) bool {
	if !buf.SuffixesSorted {
		// Because the Pwned Passwords API does not explicitly claim
		// that the returned suffixes are sorted (though in practice
		// this appears to be the case), if parsing detected that
		// they're not sorted, the quickest way is to loop through all
		// suffixes.

		for _, s := range buf.Suffixes {
			if bytes.Equal(s, suffix) {
				return true
			}
		}

		return false
	}

	// Suffixes are sorted, so we can use binary search to quickly find
	// whether the suffix is in buf.Suffixes.

	suffixBytes := []byte(suffix)

	index := sort.Search(len(buf.Suffixes), func(i int) bool {
		return bytes.Compare(buf.Suffixes[i], suffixBytes) >= 0
	})

	if index < len(buf.Suffixes) {
		return bytes.Equal(suffixBytes, buf.Suffixes[index])
	}

	return false
}

// doRequest finally sends a request to the Pwned Passwords API and uses buf to
// read and parse the result into.
func (c *PwnedClient) doRequest(ctx context.Context, buf *pwnedResultBuffer, prefix []byte) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, PwnedPasswordsURL(string(prefix)), nil)
	if err != nil {
		return nil, err
	}

	userAgent := c.UserAgent

	if userAgent == "" {
		userAgent = DefaultUserAgent
	}

	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	client := c.HTTP
	if client == nil {
		client = http.DefaultClient
	}

	res, err := client.Do(req)
	if err != nil {
		return res, err
	}

	originalBody := res.Body
	defer originalBody.Close()

	if res.StatusCode == http.StatusOK {
		_, err = buf.Buffer.ReadFrom(originalBody)
		if err != nil {
			return res, err
		}

		defer buf.Buffer.Reset()

		buf.Parse()
		if c.Cache != nil && len(buf.Suffixes) > 0 {
			if err := c.Cache.Add(ctx, prefix, buf.Suffixes); err != nil {
				return res, err
			}
		}

		res.Body = buf
	}

	return res, nil
}

// Check uses the Pwned Passwords API to check if the provided password is
// found in a breach. If two concurrent calls are made with passwords that
// share the same SHA1 prefix, only a single request will be sent. You can
// cancel the context to cancel long-running requests.
//
// Unexpected HTTPS responses will return ErrorUnexpectedResponse.
func (c *PwnedClient) Check(ctx context.Context, password string) (bool, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	sum := sha1.Sum([]byte(password))
	hexsum := []byte(strings.ToUpper(hex.EncodeToString(sum[:])))
	prefix := hexsum[:5]
	suffix := hexsum[5:]

	if c.Cache != nil {
		contains, err := c.Cache.Contains(ctx, prefix, suffix)
		if err != nil {
			return contains, err
		}

		if contains {
			return true, nil
		}
	}

	box := c.doCheck(ctx, prefix)
	defer box.Release()

	res, err := box.Value()
	if err != nil {
		return false, err
	}

	if res.StatusCode != http.StatusOK {
		return false, &ErrorUnexpectedResponse{
			Response: res,
		}
	}

	buf := res.Body.(*pwnedResultBuffer)

	return buf.Lookup(suffix), nil
}

func (c *PwnedClient) doCheck(ctx context.Context, prefix []byte) *refcountBox[func() (*http.Response, error)] {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.requests == nil {
		c.requests = make(map[string]*refcountBox[func() (*http.Response, error)])
	}

	prefixString := string(prefix)

	box, ok := c.requests[prefixString]
	if !ok {
		buffer := bufferPool.Get().(*bytes.Buffer)
		suffixes := suffixesPool.Get().(*[][]byte)

		box = &refcountBox[func() (*http.Response, error)]{
			Value: sync.OnceValues(func() (*http.Response, error) {
				return c.doRequest(ctx, &pwnedResultBuffer{
					Buffer:   buffer,
					Suffixes: *suffixes,
				}, prefix)
			}),
			OnRelease: func() {
				c.releaseRequest(prefixString)

				bufferPool.Put(buffer)
				suffixesPool.Put(suffixes)
			},
		}

		c.requests[prefixString] = box
	}

	box.Acquire()

	return box
}

func (c *PwnedClient) releaseRequest(prefix string) {
	c.lock.Lock()
	defer c.lock.Unlock()

	if c.requests != nil {
		delete(c.requests, prefix)
	}
}
