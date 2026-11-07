package restore

import (
	"bytes"
	"io"

	"github.com/epiclabs-io/diff3"
)

// MergeAgainstVerifiedBase attempts a three-way merge only when the current
// file is byte-for-byte equal to a version from the already-verified catalog
// history. That equality is the proof that the historical version is a common
// base; filenames and timestamps are not used as evidence.
func MergeAgainstVerifiedBase(current, incoming []byte, verifiedHistory [][]byte) (merged []byte, usedBase, conflicts bool, err error) {
	if bytes.IndexByte(current, 0) >= 0 || bytes.IndexByte(incoming, 0) >= 0 {
		return nil, false, false, nil
	}
	for _, base := range verifiedHistory {
		if bytes.IndexByte(base, 0) >= 0 || !bytes.Equal(current, base) {
			continue
		}
		result, mergeErr := diff3.Merge(bytes.NewReader(current), bytes.NewReader(base), bytes.NewReader(incoming), true, "current", "snapshot")
		if mergeErr != nil {
			return nil, true, false, mergeErr
		}
		if result == nil || result.Result == nil {
			return nil, true, false, io.ErrUnexpectedEOF
		}
		merged, err = io.ReadAll(result.Result)
		if err != nil {
			return nil, true, false, err
		}
		// diff3's reader output omits a final line break. Preserve the incoming
		// snapshot's final-newline convention when producing a clean merge.
		if !result.Conflicts && len(incoming) > 0 && incoming[len(incoming)-1] == '\n' && (len(merged) == 0 || merged[len(merged)-1] != '\n') {
			merged = append(merged, '\n')
		}
		return merged, true, result.Conflicts, nil
	}
	return nil, false, false, nil
}
