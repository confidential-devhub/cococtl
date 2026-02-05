package trustee

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetKBSPodName_Found(t *testing.T) {
	// Setup fake clientset with KBS pod
	fakeClient := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kbs-pod-1",
				Namespace: "trustee-ns",
				Labels:    map[string]string{"app": "kbs"},
			},
		},
	)

	ctx := context.Background()
	podName, err := GetKBSPodName(ctx, fakeClient, "trustee-ns")
	if err != nil {
		t.Fatalf("GetKBSPodName() error = %v, want nil", err)
	}

	expectedName := "kbs-pod-1"
	if podName != expectedName {
		t.Errorf("GetKBSPodName() = %v, want %v", podName, expectedName)
	}
}

func TestGetKBSPodName_NotFound(t *testing.T) {
	// Empty fake clientset - no pods
	fakeClient := fake.NewSimpleClientset()

	ctx := context.Background()
	podName, err := GetKBSPodName(ctx, fakeClient, "trustee-ns")
	if err == nil {
		t.Fatalf("GetKBSPodName() error = nil, want error")
	}

	if podName != "" {
		t.Errorf("GetKBSPodName() = %v, want empty string on error", podName)
	}

	expectedErr := "no KBS pod found in namespace trustee-ns"
	if err.Error() != expectedErr {
		t.Errorf("GetKBSPodName() error = %v, want %v", err.Error(), expectedErr)
	}
}

func TestGetKBSPodName_MultiplePods(t *testing.T) {
	// Setup fake clientset with multiple KBS pods
	fakeClient := fake.NewSimpleClientset(
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kbs-pod-1",
				Namespace: "trustee-ns",
				Labels:    map[string]string{"app": "kbs"},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "kbs-pod-2",
				Namespace: "trustee-ns",
				Labels:    map[string]string{"app": "kbs"},
			},
		},
		&corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "other-pod",
				Namespace: "trustee-ns",
				Labels:    map[string]string{"app": "other"},
			},
		},
	)

	ctx := context.Background()
	podName, err := GetKBSPodName(ctx, fakeClient, "trustee-ns")
	if err != nil {
		t.Fatalf("GetKBSPodName() error = %v, want nil", err)
	}

	// Should return first matching pod
	expectedName := "kbs-pod-1"
	if podName != expectedName {
		t.Errorf("GetKBSPodName() = %v, want %v (first pod)", podName, expectedName)
	}
}
