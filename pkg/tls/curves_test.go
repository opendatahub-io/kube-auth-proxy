package tls

import (
	cryptotls "crypto/tls"
	"testing"
)

func TestParseCurvePreferences(t *testing.T) {
	got, err := ParseCurvePreferences([]string{"23", "29", "4588", "4587", "4589"})
	if err != nil {
		t.Fatalf("ParseCurvePreferences() returned an error: %v", err)
	}
	want := []cryptotls.CurveID{
		cryptotls.CurveP256,
		cryptotls.X25519,
		cryptotls.X25519MLKEM768,
		cryptotls.SecP256r1MLKEM768,
		cryptotls.SecP384r1MLKEM1024,
	}
	for _, curve := range want {
		found := false
		for _, actual := range got {
			if actual == curve {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("curve %v is missing from %v", curve, got)
		}
	}
}

func TestParseCurvePreferencesRejectsInvalidInput(t *testing.T) {
	for _, values := range [][]string{{"0"}, {"65536"}, {"23", "23"}, {"not-a-number"}} {
		if _, err := ParseCurvePreferences(values); err == nil {
			t.Errorf("ParseCurvePreferences(%v) returned no error", values)
		}
	}
}
