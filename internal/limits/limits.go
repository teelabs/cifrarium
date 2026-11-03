package limits

import (
	"fmt"
	"io"
)

const (
	MaxCapturedFileBytes   int64 = 16 << 20
	MaxSnapshotPlainBytes  int64 = 64 << 20
	MaxSnapshotCipherBytes int64 = 64 << 20
	MaxManifestBytes       int64 = 1 << 20
	MaxQueueItemBytes      int64 = 64 << 20
	MaxQueueFileBytes      int64 = 64 << 20
	MaxMCPLineBytes        int   = 64 << 10
	MaxCapturedFiles       int   = 4096
	MaxPathBytes           int   = 4096
	MaxPathDepth           int   = 64
)

func ReadAll(r io.Reader, max int64) ([]byte, error) {
	if max < 0 {
		return nil, fmt.Errorf("invalid read limit")
	}
	b, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("input exceeds %d-byte limit", max)
	}
	return b, nil
}

func CheckBytes(size int, max int64) error {
	if int64(size) > max {
		return fmt.Errorf("input exceeds %d-byte limit", max)
	}
	return nil
}
