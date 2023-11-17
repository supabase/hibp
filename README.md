# Pwned Passwords API in Go

This library implements the [HaveIBeenPwned.org's Pwned Passwords v3
API](https://haveibeenpwned.com/API/v3#PwnedPasswords) in Go.

Features:

- No external dependencies to reduce the likelihood of supply-chain attacks.
- Cache support, as API responses can sometimes be huge.
- Concurrent request optimization. Sharing a single request for password hash
  prefix.
- Efficient memory use, no large allocations.

Example:

```go
import (
	"github.com/supabase/hibp"
)

func main() {
	pwnedClient := hibp.PwnedClient{
		// please always set a User-Agent identifying your project
		UserAgent: "my-super-cool-project",
	}

	isPwned, err := pwnedClient.Check(context.Background(), "password1")
	if err != nil {
		if ur, ok := err.(*hibp.ErrorUnknownResponse); ok {
			// any non-200 response available in ur.Response
		}

		panic(err)
	}

	fmt.Print("Your password is ")
	if isPwned {
		fmt.Print("pwned!\n")
	} else {
		fmt.Print("safe for now!\n")
	}
}
```

## License

Maintained by the [Auth](https://supabase.com/docs/guides/auth) team at
[Supabase](https://supabase.com). Licensed under the MIT License.
