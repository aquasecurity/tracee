package intern

import (
	"runtime"
	"testing"
)

// simulatedEvent mimics the string fields of trace.Event that benefit from interning.
type simulatedEvent struct {
	ProcessName  string
	HostName     string
	ContainerID  string
	ImageName    string
	ImageDigest  string
	PodName      string
	PodNamespace string
	// Argument strings (file paths, program names)
	ArgPath    string
	ArgProgram string
}

// processNames represents the limited set of unique process names on a typical system.
var processNames = []string{
	"bash", "nginx", "sshd", "tracee", "kubelet", "containerd",
	"kube-proxy", "coredns", "etcd", "kube-apiserver",
}

// containerIDs represents a moderate number of running containers.
var containerIDs = []string{
	"abc123def456", "789ghi012jkl", "345mno678pqr", "901stu234vwx",
	"567yza890bcd", "efg111hij222", "klm333nop444", "qrs555tuv666",
}

var images = []string{
	"docker.io/library/nginx:1.25", "docker.io/library/redis:7",
	"gcr.io/k8s/kube-proxy:v1.28", "docker.io/library/postgres:16",
}

var imageDigests = []string{
	"sha256:aaaaaaaabbbbbbbbccccccccddddddddeeeeeeeeffffffff0000000011111111",
	"sha256:2222222233333333444444445555555566666666777777778888888899999999",
}

var podNames = []string{
	"nginx-deployment-abc123", "redis-master-xyz789",
	"kube-proxy-node01", "coredns-5d78c9869d-abcde",
}

var podNamespaces = []string{
	"default", "kube-system", "monitoring", "production",
}

var argPaths = []string{
	"/usr/bin/bash", "/usr/sbin/nginx", "/usr/bin/redis-server",
	"/etc/nginx/nginx.conf", "/etc/resolv.conf", "/proc/self/exe",
	"/usr/lib/x86_64-linux-gnu/libc.so.6", "/dev/null",
}

var argPrograms = []string{
	"bash", "nginx", "redis-server", "postgres", "kubelet", "containerd-shim",
}

const hostname = "worker-node-01.k8s.cluster.local"

// BenchmarkEventPipeline_WithInterning simulates building N events with interning.
// It measures both the allocation count/bytes and gives a sense of steady-state memory.
func BenchmarkEventPipeline_WithInterning(b *testing.B) {
	events := make([]simulatedEvent, 0, b.N)
	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		// Simulate byte-buffer-to-string conversions (the real allocation source).
		commBytes := []byte(processNames[i%len(processNames)])
		hostBytes := []byte(hostname)
		cid := containerIDs[i%len(containerIDs)]
		img := images[i%len(images)]
		dig := imageDigests[i%len(imageDigests)]
		pod := podNames[i%len(podNames)]
		ns := podNamespaces[i%len(podNamespaces)]
		path := []byte(argPaths[i%len(argPaths)])
		prog := []byte(argPrograms[i%len(argPrograms)])

		events = append(events, simulatedEvent{
			ProcessName:  String(string(commBytes)),
			HostName:     String(string(hostBytes)),
			ContainerID:  String(cid),
			ImageName:    String(img),
			ImageDigest:  String(dig),
			PodName:      String(pod),
			PodNamespace: String(ns),
			ArgPath:      String(string(path)),
			ArgProgram:   String(string(prog)),
		})
	}
	runtime.KeepAlive(events)
}

// BenchmarkEventPipeline_WithoutInterning is the baseline: no interning.
func BenchmarkEventPipeline_WithoutInterning(b *testing.B) {
	events := make([]simulatedEvent, 0, b.N)
	b.ResetTimer()
	b.ReportAllocs()

	for i := range b.N {
		commBytes := []byte(processNames[i%len(processNames)])
		hostBytes := []byte(hostname)
		cid := containerIDs[i%len(containerIDs)]
		img := images[i%len(images)]
		dig := imageDigests[i%len(imageDigests)]
		pod := podNames[i%len(podNames)]
		ns := podNamespaces[i%len(podNamespaces)]
		path := []byte(argPaths[i%len(argPaths)])
		prog := []byte(argPrograms[i%len(argPrograms)])

		events = append(events, simulatedEvent{
			ProcessName:  string(commBytes),
			HostName:     string(hostBytes),
			ContainerID:  cid,
			ImageName:    img,
			ImageDigest:  dig,
			PodName:      pod,
			PodNamespace: ns,
			ArgPath:      string(path),
			ArgProgram:   string(prog),
		})
	}
	runtime.KeepAlive(events)
}

// BenchmarkRSSEstimate runs a large number of simulated events and reports
// heap memory before and after, giving a realistic estimate of RSS savings.
//
// ReadMemStats triggers a STW pause on each call; this is acceptable because
// the framework will keep b.N very low (typically 1) given the cost per iteration.
func BenchmarkRSSEstimate(b *testing.B) {
	const numEvents = 500_000

	b.Run("WithInterning", func(b *testing.B) {
		for range b.N {
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)

			events := make([]simulatedEvent, numEvents)
			for i := range numEvents {
				commBytes := []byte(processNames[i%len(processNames)])
				hostBytes := []byte(hostname)
				pathBytes := []byte(argPaths[i%len(argPaths)])
				progBytes := []byte(argPrograms[i%len(argPrograms)])

				events[i] = simulatedEvent{
					ProcessName:  String(string(commBytes)),
					HostName:     String(string(hostBytes)),
					ContainerID:  String(containerIDs[i%len(containerIDs)]),
					ImageName:    String(images[i%len(images)]),
					ImageDigest:  String(imageDigests[i%len(imageDigests)]),
					PodName:      String(podNames[i%len(podNames)]),
					PodNamespace: String(podNamespaces[i%len(podNamespaces)]),
					ArgPath:      String(string(pathBytes)),
					ArgProgram:   String(string(progBytes)),
				}
			}

			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			heapMB := float64(after.HeapInuse-before.HeapInuse) / (1024 * 1024)
			b.ReportMetric(heapMB, "heap-MB")
			runtime.KeepAlive(events)
		}
	})

	b.Run("WithoutInterning", func(b *testing.B) {
		for range b.N {
			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)

			events := make([]simulatedEvent, numEvents)
			for i := range numEvents {
				commBytes := []byte(processNames[i%len(processNames)])
				hostBytes := []byte(hostname)
				pathBytes := []byte(argPaths[i%len(argPaths)])
				progBytes := []byte(argPrograms[i%len(argPrograms)])

				events[i] = simulatedEvent{
					ProcessName:  string(commBytes),
					HostName:     string(hostBytes),
					ContainerID:  containerIDs[i%len(containerIDs)],
					ImageName:    images[i%len(images)],
					ImageDigest:  imageDigests[i%len(imageDigests)],
					PodName:      podNames[i%len(podNames)],
					PodNamespace: podNamespaces[i%len(podNamespaces)],
					ArgPath:      string(pathBytes),
					ArgProgram:   string(progBytes),
				}
			}

			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			heapMB := float64(after.HeapInuse-before.HeapInuse) / (1024 * 1024)
			b.ReportMetric(heapMB, "heap-MB")
			runtime.KeepAlive(events)
		}
	})

	b.Log("NOTE: Compare heap-MB between WithInterning and WithoutInterning.")
	b.Log("The interned version should use significantly less heap memory for string backing arrays.")
}
