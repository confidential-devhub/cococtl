package trustee

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	k8swatch "k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// readyPod returns a pod with the Ready condition set to True.
func readyPod(name, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app": "kbs"},
		},
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionTrue},
			},
		},
	}
}

// notReadyPod returns a pod with no Ready condition.
func notReadyPod(name, namespace string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
			Labels:    map[string]string{"app": "kbs"},
		},
	}
}

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

// --- isPodReady tests ---

func TestIsPodReady_Ready(t *testing.T) {
	if !isPodReady(readyPod("p", "ns")) {
		t.Error("isPodReady() = false for a pod with Ready=True, want true")
	}
}

func TestIsPodReady_NotReady(t *testing.T) {
	if isPodReady(notReadyPod("p", "ns")) {
		t.Error("isPodReady() = true for a pod with no Ready condition, want false")
	}
}

func TestIsPodReady_ConditionFalse(t *testing.T) {
	pod := &corev1.Pod{
		Status: corev1.PodStatus{
			Conditions: []corev1.PodCondition{
				{Type: corev1.PodReady, Status: corev1.ConditionFalse},
			},
		},
	}
	if isPodReady(pod) {
		t.Error("isPodReady() = true for a pod with Ready=False, want false")
	}
}

// --- WaitForKBSReady tests ---

func TestWaitForKBSReady_AlreadyReady(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(readyPod("kbs-pod", "trustee-ns"))

	ctx := context.Background()
	if err := WaitForKBSReady(ctx, fakeClient, "trustee-ns"); err != nil {
		t.Fatalf("WaitForKBSReady() error = %v, want nil", err)
	}
}

func TestWaitForKBSReady_NoPods(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately so the watch returns right away

	err := WaitForKBSReady(ctx, fakeClient, "trustee-ns")
	if err == nil {
		t.Fatal("WaitForKBSReady() error = nil, want context-cancelled error")
	}
}

func TestWaitForKBSReady_ContextCancelled(t *testing.T) {
	// Pod exists but is not ready.
	fakeClient := fake.NewSimpleClientset(notReadyPod("kbs-pod", "trustee-ns"))

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before calling so watch exits immediately

	err := WaitForKBSReady(ctx, fakeClient, "trustee-ns")
	if err == nil {
		t.Fatal("WaitForKBSReady() error = nil, want context-cancelled error")
	}
}

func TestWaitForKBSReady_BecomesReady(t *testing.T) {
	fakeClient := fake.NewSimpleClientset(notReadyPod("kbs-pod", "trustee-ns"))

	fw := k8swatch.NewFake()
	fakeClient.PrependWatchReactor("pods", func(_ k8stesting.Action) (bool, k8swatch.Interface, error) {
		return true, fw, nil
	})

	// Inject a Modified event carrying a ready pod after the watch is consumed.
	go fw.Modify(readyPod("kbs-pod", "trustee-ns"))

	if err := WaitForKBSReady(context.Background(), fakeClient, "trustee-ns"); err != nil {
		t.Fatalf("WaitForKBSReady() error = %v, want nil", err)
	}
}

func TestWaitForKBSReady_DeletedThenReady(t *testing.T) {
	// A Deleted event must not abort the wait; a subsequent Modified with a
	// ready pod should succeed.
	fakeClient := fake.NewSimpleClientset(notReadyPod("kbs-pod", "trustee-ns"))

	fw := k8swatch.NewFake()
	fakeClient.PrependWatchReactor("pods", func(_ k8stesting.Action) (bool, k8swatch.Interface, error) {
		return true, fw, nil
	})

	go func() {
		fw.Delete(notReadyPod("kbs-pod", "trustee-ns"))
		fw.Modify(readyPod("kbs-pod-2", "trustee-ns"))
	}()

	if err := WaitForKBSReady(context.Background(), fakeClient, "trustee-ns"); err != nil {
		t.Fatalf("WaitForKBSReady() error = %v, want nil (Deleted should be ignored)", err)
	}
}

func TestWaitForKBSReady_WatchClosedRelists(t *testing.T) {
	// When the watch channel closes normally, WaitForKBSReady must re-list.
	// Set up: first watch closes immediately; the re-list finds the pod ready.
	fakeClient := fake.NewSimpleClientset(notReadyPod("kbs-pod", "trustee-ns"))

	fw := k8swatch.NewFake()
	watchEstablished := make(chan struct{}, 1)
	fakeClient.PrependWatchReactor("pods", func(_ k8stesting.Action) (bool, k8swatch.Interface, error) {
		select {
		case watchEstablished <- struct{}{}:
		default:
		}
		return true, fw, nil
	})

	go func() {
		<-watchEstablished
		// Update the pod to ready in the tracker so the re-list finds it ready.
		if err := fakeClient.Tracker().Update(
			corev1.SchemeGroupVersion.WithResource("pods"),
			readyPod("kbs-pod", "trustee-ns"),
			"trustee-ns",
		); err != nil {
			return
		}
		fw.Stop() // close the watch channel, triggering re-list
	}()

	if err := WaitForKBSReady(context.Background(), fakeClient, "trustee-ns"); err != nil {
		t.Fatalf("WaitForKBSReady() error = %v, want nil after re-list", err)
	}
}
