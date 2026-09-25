package utils

import (
	"testing"
)

func TestMsValidVectors(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"7d", 7 * 86400000},
		{"30m", 30 * 60000},
		{"1 hour", 3600000},
		{"2 hours", 7200000},
		{"30s", 30000},
		{"1d", 86400000},
		{"1w", 604800000},
		{"1mo", 2592000000},
		{"1month", 2592000000},
		{"1months", 2592000000},
		{"1y", 31557600000},
		{"1yr", 31557600000},
		{"1yrs", 31557600000},
		{"1year", 31557600000},
		{"1years", 31557600000},
		{"1.5h", 5400000},
		{"2 hours ago", -7200000},
		{"-5m", -300000},
		{"+5m", 300000},
		{"+ 5m", 300000},
		{"- 5m", -300000},
		{"5m from now", 300000},
		{"5D", 5 * 86400000},
		{"1 HOUR", 3600000},
		{"1 Hour", 3600000},
		{"10 sec", 10000},
		{"1 min", 60000},
		{"1 secs", 1000},
		{"1 mins", 60000},
		{"1 hrs", 3600000},
		{"1 hr", 3600000},
		{"1 days", 86400000},
		{"1 weeks", 604800000},
		{"1 seconds", 1000},
		{"1 minutes", 60000},
		{"1 Seconds Ago", -1000},
		{"1 hour From Now", 3600000},
	}
	for _, c := range cases {
		got, err := Ms(c.in)
		if err != nil {
			t.Errorf("Ms(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Ms(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestSecValidVectors(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"1d", 86400},
		{"2 hours", 7200},
		{"-30s", -30},
		{"2 hours ago", -7200},
		{"7d", 604800},
		{"30m", 1800},
		{"1.5s", 2},
		{"1499ms-invalid-should-error-skip", 0},
	}
	for _, c := range cases {
		if c.in == "1499ms-invalid-should-error-skip" {
			continue
		}
		got, err := Sec(c.in)
		if err != nil {
			t.Errorf("Sec(%q) error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Sec(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestMsSecAgree(t *testing.T) {
	ms, err := Ms("7d")
	if err != nil {
		t.Fatal(err)
	}
	sec, err := Sec("7d")
	if err != nil {
		t.Fatal(err)
	}
	if ms/1000 != sec {
		t.Fatalf("Ms(7d)/1000 = %d, Sec(7d) = %d", ms/1000, sec)
	}
}

func TestTimeStringInvalid(t *testing.T) {
	invalid := []string{
		"",
		"abc",
		"5",
		"5x",
		"100ms",
		"+5m ago",
		"-5m from now",
		"+5m from now",
		"-5m ago",
		"5m yesterday",
		".5h",
		"5.",
		"ago",
		"from now",
		"5  m",
		"++5m",
		"--5m",
		"5m  ago",
		"m",
		"s",
	}
	for _, in := range invalid {
		if _, err := Ms(in); err == nil {
			t.Errorf("Ms(%q) = nil error, want error", in)
		}
		if _, err := Sec(in); err == nil {
			t.Errorf("Sec(%q) = nil error, want error", in)
		}
	}
}
