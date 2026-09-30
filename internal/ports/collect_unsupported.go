//go:build !linux

package ports

import (
	"fmt"
	"runtime"
)

func Collect(opts Options) (Result, error) {
	return Result{}, fmt.Errorf("portwho: %s backend is not implemented", runtime.GOOS)
}
