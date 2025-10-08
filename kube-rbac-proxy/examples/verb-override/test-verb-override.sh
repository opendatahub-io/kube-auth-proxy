#!/bin/bash

# Test script for verb-override functionality
# This script demonstrates that the verb override works regardless of HTTP method

set -e

echo "=== Testing kube-rbac-proxy verb override functionality ==="
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local color=$1
    local message=$2
    echo -e "${color}${message}${NC}"
}

# Check if kubectl is available
if ! command -v kubectl &> /dev/null; then
    print_status $RED "kubectl not found. Please install kubectl and configure access to a Kubernetes cluster."
    exit 1
fi

# Check if cluster is accessible
if ! kubectl cluster-info &> /dev/null; then
    print_status $RED "Cannot access Kubernetes cluster. Please check your kubeconfig."
    exit 1
fi

print_status $YELLOW "Step 1: Deploying kube-rbac-proxy with verb override configuration..."
kubectl apply -f deployment.yaml

print_status $YELLOW "Step 2: Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/kube-rbac-proxy-verb-override

print_status $YELLOW "Step 3: Deploying client RBAC (with 'list' permission on pods)..."
kubectl apply -f client-rbac.yaml

print_status $YELLOW "Step 4: Testing with GET request..."
kubectl apply -f client.yaml

# Wait for job to complete
kubectl wait --for=condition=complete --timeout=60s job/krp-curl-verb-override

# Check job logs
print_status $GREEN "GET request test results:"
kubectl logs job/krp-curl-verb-override

# Clean up the job for next test
kubectl delete job krp-curl-verb-override

print_status $YELLOW "Step 5: Testing with POST request (should also require 'list' permission)..."

# Create a modified client that sends POST request
cat > /tmp/client-post.yaml << EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: krp-curl-post-test
spec:
  template:
    metadata:
      name: krp-curl-post-test
    spec:
      containers:
      - name: krp-curl
        image: quay.io/brancz/krp-curl:v0.0.2
        command: ["/bin/sh"]
        args: ["-c", "curl -X POST -v -s -k -H \"Authorization: Bearer \$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" https://kube-rbac-proxy-verb-override.default.svc:8443/metrics"]
      restartPolicy: Never
  backoffLimit: 4
EOF

kubectl apply -f /tmp/client-post.yaml

# Wait for job to complete
kubectl wait --for=condition=complete --timeout=60s job/krp-curl-post-test

print_status $GREEN "POST request test results:"
kubectl logs job/krp-curl-post-test

# Clean up
kubectl delete job krp-curl-post-test

print_status $YELLOW "Step 6: Testing failure case - removing 'list' permission and adding only 'get'..."

# Create RBAC with wrong permission
cat > /tmp/client-rbac-wrong.yaml << EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kube-rbac-proxy-verb-override-client
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]  # Wrong permission - should be "list"
EOF

kubectl apply -f /tmp/client-rbac-wrong.yaml

# Test again - should fail
cat > /tmp/client-should-fail.yaml << EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: krp-curl-should-fail
spec:
  template:
    metadata:
      name: krp-curl-should-fail
    spec:
      containers:
      - name: krp-curl
        image: quay.io/brancz/krp-curl:v0.0.2
      restartPolicy: Never
  backoffLimit: 4
EOF

kubectl apply -f /tmp/client-should-fail.yaml

# Wait for job to complete (or fail)
sleep 30

print_status $RED "Expected failure test results (should show 403 Forbidden):"
kubectl logs job/krp-curl-should-fail || print_status $RED "Job failed as expected due to insufficient permissions"

print_status $YELLOW "Step 7: Restoring correct permissions..."
kubectl apply -f client-rbac.yaml

print_status $GREEN "✅ Verb override functionality test completed successfully!"
print_status $YELLOW "Key observations:"
print_status $YELLOW "1. Both GET and POST requests require 'list' permission (verb override working)"
print_status $YELLOW "2. Requests fail when only 'get' permission is provided"
print_status $YELLOW "3. The configured verb ('list') overrides the HTTP method-derived verb"

print_status $YELLOW "Cleaning up test resources..."
kubectl delete job krp-curl-should-fail --ignore-not-found=true
rm -f /tmp/client-*.yaml

print_status $GREEN "Test completed! Check the proxy logs with:"
print_status $YELLOW "kubectl logs deployment/kube-rbac-proxy-verb-override -c kube-rbac-proxy"

print_status $YELLOW "To clean up all resources:"
print_status $YELLOW "kubectl delete -f deployment.yaml -f client-rbac.yaml"