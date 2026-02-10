package cluster

import (
	"context"
	"sort"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestGetNodeIPs_ExternalIP(t *testing.T) {
	// Setup fake clientset with 2 nodes, each having both ExternalIP and InternalIP
	fakeClient := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
					{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "5.6.7.8"},
					{Type: corev1.NodeInternalIP, Address: "10.0.0.2"},
				},
			},
		},
	)

	ctx := context.Background()
	ips, err := GetNodeIPs(ctx, fakeClient)
	if err != nil {
		t.Fatalf("GetNodeIPs() error = %v", err)
	}

	// Should prefer external IPs
	if len(ips) != 2 {
		t.Errorf("GetNodeIPs() returned %d IPs, want 2", len(ips))
	}

	// Check external IPs are returned (order may vary)
	sort.Strings(ips)
	expected := []string{"1.2.3.4", "5.6.7.8"}
	sort.Strings(expected)

	if len(ips) != len(expected) {
		t.Errorf("GetNodeIPs() = %v, want %v", ips, expected)
		return
	}
	for i := range ips {
		if ips[i] != expected[i] {
			t.Errorf("GetNodeIPs() = %v, want %v", ips, expected)
			return
		}
	}
}

func TestGetNodeIPs_FallbackToInternal(t *testing.T) {
	// Setup fake clientset with 2 nodes, only InternalIP (no ExternalIP)
	fakeClient := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeInternalIP, Address: "10.0.0.2"},
				},
			},
		},
	)

	ctx := context.Background()
	ips, err := GetNodeIPs(ctx, fakeClient)
	if err != nil {
		t.Fatalf("GetNodeIPs() error = %v", err)
	}

	// Should fall back to internal IPs
	if len(ips) != 2 {
		t.Errorf("GetNodeIPs() returned %d IPs, want 2", len(ips))
	}

	sort.Strings(ips)
	expected := []string{"10.0.0.1", "10.0.0.2"}
	sort.Strings(expected)

	for i := range ips {
		if ips[i] != expected[i] {
			t.Errorf("GetNodeIPs() = %v, want %v", ips, expected)
			return
		}
	}
}

func TestGetNodeIPs_NoNodes(t *testing.T) {
	// Setup empty fake clientset (no Nodes)
	fakeClient := fake.NewSimpleClientset()

	ctx := context.Background()
	_, err := GetNodeIPs(ctx, fakeClient)
	if err == nil {
		t.Fatal("GetNodeIPs() expected error for empty cluster, got nil")
	}

	if !strings.Contains(err.Error(), "no node IPs found") {
		t.Errorf("GetNodeIPs() error = %q, want error containing 'no node IPs found'", err.Error())
	}
}

func TestGetNodeIPs_NoAddresses(t *testing.T) {
	// Setup fake clientset with node that has no addresses
	fakeClient := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{},
			},
		},
	)

	ctx := context.Background()
	_, err := GetNodeIPs(ctx, fakeClient)
	if err == nil {
		t.Fatal("GetNodeIPs() expected error for node with no addresses, got nil")
	}

	if !strings.Contains(err.Error(), "no node IPs found") {
		t.Errorf("GetNodeIPs() error = %q, want error containing 'no node IPs found'", err.Error())
	}
}

func TestGetNodeIPs_Deduplication(t *testing.T) {
	// Setup fake clientset with 2 nodes having same ExternalIP (rare but possible)
	fakeClient := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
				},
			},
		},
	)

	ctx := context.Background()
	ips, err := GetNodeIPs(ctx, fakeClient)
	if err != nil {
		t.Fatalf("GetNodeIPs() error = %v", err)
	}

	// Should return deduplicated list (single IP)
	if len(ips) != 1 {
		t.Errorf("GetNodeIPs() returned %d IPs, want 1 (deduplicated)", len(ips))
	}

	if ips[0] != "1.2.3.4" {
		t.Errorf("GetNodeIPs() = %v, want [1.2.3.4]", ips)
	}
}

func TestGetNodeIPs_MixedAddressTypes(t *testing.T) {
	// Setup fake clientset with nodes having various address types (Hostname, InternalDNS, etc.)
	fakeClient := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeHostName, Address: "node-1.example.com"},
					{Type: corev1.NodeInternalDNS, Address: "node-1.cluster.local"},
					{Type: corev1.NodeExternalIP, Address: "1.2.3.4"},
					{Type: corev1.NodeInternalIP, Address: "10.0.0.1"},
				},
			},
		},
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-2"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeHostName, Address: "node-2.example.com"},
					{Type: corev1.NodeExternalDNS, Address: "node-2.public.example.com"},
					{Type: corev1.NodeExternalIP, Address: "5.6.7.8"},
					{Type: corev1.NodeInternalIP, Address: "10.0.0.2"},
				},
			},
		},
	)

	ctx := context.Background()
	ips, err := GetNodeIPs(ctx, fakeClient)
	if err != nil {
		t.Fatalf("GetNodeIPs() error = %v", err)
	}

	// Should only return ExternalIP, not Hostname or DNS
	if len(ips) != 2 {
		t.Errorf("GetNodeIPs() returned %d IPs, want 2 (ExternalIPs only)", len(ips))
	}

	// Ensure only ExternalIPs are returned
	sort.Strings(ips)
	expected := []string{"1.2.3.4", "5.6.7.8"}
	sort.Strings(expected)

	for i := range ips {
		if ips[i] != expected[i] {
			t.Errorf("GetNodeIPs() = %v, want %v (ExternalIPs only)", ips, expected)
			return
		}
	}

	// Verify hostnames and DNS names are NOT included
	for _, ip := range ips {
		if strings.Contains(ip, "example.com") || strings.Contains(ip, "cluster.local") {
			t.Errorf("GetNodeIPs() returned hostname/DNS %q, should only return IPs", ip)
		}
	}
}

func TestGetNodeIPs_OnlyHostname(t *testing.T) {
	// Edge case: node only has Hostname, no ExternalIP or InternalIP
	fakeClient := fake.NewSimpleClientset(
		&corev1.Node{
			ObjectMeta: metav1.ObjectMeta{Name: "node-1"},
			Status: corev1.NodeStatus{
				Addresses: []corev1.NodeAddress{
					{Type: corev1.NodeHostName, Address: "node-1.example.com"},
				},
			},
		},
	)

	ctx := context.Background()
	_, err := GetNodeIPs(ctx, fakeClient)
	if err == nil {
		t.Fatal("GetNodeIPs() expected error when node only has Hostname, got nil")
	}

	if !strings.Contains(err.Error(), "no node IPs found") {
		t.Errorf("GetNodeIPs() error = %q, want error containing 'no node IPs found'", err.Error())
	}
}
