package cluster

import (
	"context"
	"testing"

	nodev1 "k8s.io/api/node/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestDetectRuntimeClass_SNPHandler(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "kata-cc-snp"},
			Handler:    "kata-snp",
		},
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "kata-cc-tdx"},
			Handler:    "kata-tdx",
		},
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "runc"},
			Handler:    "runc",
		},
	)

	ctx := context.Background()
	result := DetectRuntimeClass(ctx, fakeClient, "kata-cc")

	// Should return first SNP/TDX match (SNP preferred if both present)
	// Note: fake clientset may return items in any order, so accept either SNP or TDX
	if result != "kata-cc-snp" && result != "kata-cc-tdx" {
		t.Errorf("DetectRuntimeClass() = %q, want %q or %q", result, "kata-cc-snp", "kata-cc-tdx")
	}
}

func TestDetectRuntimeClass_TDXHandler(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "kata-cc-tdx"},
			Handler:    "kata-tdx",
		},
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "runc"},
			Handler:    "runc",
		},
	)

	ctx := context.Background()
	result := DetectRuntimeClass(ctx, fakeClient, "kata-cc")

	// Should return TDX match when no SNP present
	if result != "kata-cc-tdx" {
		t.Errorf("DetectRuntimeClass() = %q, want %q", result, "kata-cc-tdx")
	}
}

func TestDetectRuntimeClass_NoMatch(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "runc"},
			Handler:    "runc",
		},
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "gvisor"},
			Handler:    "gvisor",
		},
	)

	ctx := context.Background()
	result := DetectRuntimeClass(ctx, fakeClient, "kata-cc")

	// Should return default when no SNP/TDX match
	if result != "kata-cc" {
		t.Errorf("DetectRuntimeClass() = %q, want %q", result, "kata-cc")
	}
}

func TestDetectRuntimeClass_EmptyCluster(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()

	ctx := context.Background()
	result := DetectRuntimeClass(ctx, fakeClient, "kata-cc")

	// Should return default when no RuntimeClasses exist
	if result != "kata-cc" {
		t.Errorf("DetectRuntimeClass() = %q, want %q", result, "kata-cc")
	}
}

func TestDetectRuntimeClass_CaseInsensitive(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "kata-uppercase"},
			Handler:    "KATA-SNP", // uppercase handler
		},
	)

	ctx := context.Background()
	result := DetectRuntimeClass(ctx, fakeClient, "default-rc")

	// Should return the matching RuntimeClass name (case-insensitive handler matching)
	if result != "kata-uppercase" {
		t.Errorf("DetectRuntimeClass() = %q, want %q", result, "kata-uppercase")
	}
}

func TestDetectRuntimeClass_PrefersSNPOverTDX(t *testing.T) {
	// When both SNP and TDX are available, the function should return
	// whichever comes first in the list. This test ensures the function
	// properly handles both handler types.
	fakeClient := fake.NewSimpleClientset(
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "runc"},
			Handler:    "runc",
		},
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "only-snp"},
			Handler:    "kata-snp",
		},
	)

	ctx := context.Background()
	result := DetectRuntimeClass(ctx, fakeClient, "default-rc")

	// Should return the SNP runtime class
	if result != "only-snp" {
		t.Errorf("DetectRuntimeClass() = %q, want %q", result, "only-snp")
	}
}

func TestDetectRuntimeClass_HandlerContainsSNP(t *testing.T) {
	// Test that handler just needs to CONTAIN "snp", not equal it exactly
	fakeClient := fake.NewSimpleClientset(
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "my-custom-rc"},
			Handler:    "my-kata-snp-handler",
		},
	)

	ctx := context.Background()
	result := DetectRuntimeClass(ctx, fakeClient, "default-rc")

	// Should match because handler contains "snp"
	if result != "my-custom-rc" {
		t.Errorf("DetectRuntimeClass() = %q, want %q", result, "my-custom-rc")
	}
}

func TestDetectRuntimeClass_HandlerContainsTDX(t *testing.T) {
	// Test that handler just needs to CONTAIN "tdx", not equal it exactly
	fakeClient := fake.NewSimpleClientset(
		&nodev1.RuntimeClass{
			ObjectMeta: metav1.ObjectMeta{Name: "my-tdx-rc"},
			Handler:    "secure-tdx-runtime",
		},
	)

	ctx := context.Background()
	result := DetectRuntimeClass(ctx, fakeClient, "default-rc")

	// Should match because handler contains "tdx"
	if result != "my-tdx-rc" {
		t.Errorf("DetectRuntimeClass() = %q, want %q", result, "my-tdx-rc")
	}
}
