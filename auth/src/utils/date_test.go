package utils

import (
	"testing"
	"time"
)

func TestGetDateSec(t *testing.T) {
	before := time.Now()
	got := GetDate(60, "sec")
	after := time.Now()
	lo := before.Add(60 * time.Second)
	hi := after.Add(60 * time.Second)
	if got.Before(lo.Add(-2*time.Second)) || got.After(hi.Add(2*time.Second)) {
		t.Fatalf("GetDate(60, sec) = %v, want within [%v, %v]", got, lo, hi)
	}
}

func TestGetDateMs(t *testing.T) {
	before := time.Now()
	got := GetDate(1500, "ms")
	after := time.Now()
	lo := before.Add(1500 * time.Millisecond)
	hi := after.Add(1500 * time.Millisecond)
	if got.Before(lo.Add(-2*time.Second)) || got.After(hi.Add(2*time.Second)) {
		t.Fatalf("GetDate(1500, ms) = %v, want within [%v, %v]", got, lo, hi)
	}
}

func TestGetDateDefaultIsMs(t *testing.T) {
	before := time.Now()
	got := GetDate(500, "")
	after := time.Now()
	lo := before.Add(500 * time.Millisecond)
	hi := after.Add(500 * time.Millisecond)
	if got.Before(lo.Add(-2*time.Second)) || got.After(hi.Add(2*time.Second)) {
		t.Fatalf("GetDate(500, default) = %v, want ms window [%v, %v]", got, lo, hi)
	}
}

func TestGetDateUnknownUnitIsMs(t *testing.T) {
	before := time.Now()
	got := GetDate(250, "bogus")
	after := time.Now()
	lo := before.Add(250 * time.Millisecond)
	hi := after.Add(250 * time.Millisecond)
	if got.Before(lo.Add(-2*time.Second)) || got.After(hi.Add(2*time.Second)) {
		t.Fatalf("GetDate(250, bogus) = %v, want ms window [%v, %v]", got, lo, hi)
	}
}

func TestGetDateSecMatchesMsArithmetic(t *testing.T) {
	a := GetDate(2, "sec")
	b := GetDate(2000, "ms")
	if d := a.Sub(b); d < -2*time.Second || d > 2*time.Second {
		t.Fatalf("GetDate(2,sec) - GetDate(2000,ms) = %v, want ~0", d)
	}
}
