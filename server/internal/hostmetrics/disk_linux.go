//go:build linux

package hostmetrics

import "syscall"

func disk(path string) (total, used uint64) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return 0, 0
	}
	bs := uint64(st.Bsize)
	total = st.Blocks * bs
	free := st.Bfree * bs
	if free > total {
		return total, 0
	}
	return total, total - free
}
