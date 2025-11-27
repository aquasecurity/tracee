package integration

// Common constants used across integration tests

const (
	// busyboxImage is the pinned busybox image used in integration tests
	// Using ECR Public mirror to avoid Docker Hub rate limits
	busyboxImage = "public.ecr.aws/docker/library/busybox:1.37.0@sha256:e3652a00a2fabd16ce889f0aa32c38eec347b997e73bd09e69c962ec7f8732ee"

	// ubuntuJammyPinnedImage is the pinned Ubuntu Jammy image used in integration tests
	// Fixed version ensures consistent library versions for filter tests
	// Using ECR Public mirror to avoid Docker Hub rate limits
	ubuntuJammyPinnedImage = "public.ecr.aws/docker/library/ubuntu:jammy-20240911.1@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97"
)
