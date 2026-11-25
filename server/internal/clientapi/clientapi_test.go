package clientapi

import "testing"

func TestNewerVersion(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"1.326.930", "1.326.929", true},
		{"1.327.0", "1.326.1439", true},
		{"2.0.0", "1.999.999", true},
		{"1.326.929", "1.326.930", false},
		{"1.326.930", "1.326.930", false},
		{"1.326.930", "dev", false}, // dev builds never auto-update
		{"garbage", "1.0.0", false},
		{"v1.2.4", "1.2.3", true},
	}
	for _, c := range cases {
		if got := NewerVersion(c.a, c.b); got != c.want {
			t.Errorf("NewerVersion(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
