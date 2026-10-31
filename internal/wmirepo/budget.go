package wmirepo

import "fmt"

type byteBudget struct{ used, limit int }

func (b *byteBudget) charge(n int) error {
	if n < 0 || b.used < 0 || b.limit < 0 || b.used > b.limit || n > b.limit-b.used {
		return fmt.Errorf("%w: aggregate structure byte budget", ErrUnsupported)
	}
	b.used += n
	return nil
}
