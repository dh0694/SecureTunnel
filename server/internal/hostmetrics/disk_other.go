//go:build !linux

package hostmetrics

func disk(string) (total, used uint64) { return 0, 0 }
