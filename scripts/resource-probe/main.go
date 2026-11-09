// SPDX-FileCopyrightText: 2026 Anthony Green
// SPDX-License-Identifier: Apache-2.0
// Independent upstream gRPC client, topology-aware device plugin, and in-container kernel probe.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	dp "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
	pr "k8s.io/kubelet/pkg/apis/podresources/v1"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func connect(path string) *grpc.ClientConn {
	c, err := grpc.NewClient("passthrough:///"+path, grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", path)
		}))
	check(err)
	return c
}

type plugin struct {
	dp.UnimplementedDevicePluginServer
	node int64
}

func (p *plugin) GetDevicePluginOptions(context.Context, *dp.Empty) (*dp.DevicePluginOptions, error) {
	return &dp.DevicePluginOptions{}, nil
}
func (p *plugin) ListAndWatch(_ *dp.Empty, stream dp.DevicePlugin_ListAndWatchServer) error {
	devices := []*dp.Device{}
	for i := 0; i < 2; i++ {
		devices = append(devices, &dp.Device{ID: fmt.Sprintf("numa%d-%d", p.node, i), Health: dp.Healthy, Topology: &dp.TopologyInfo{Nodes: []*dp.NUMANode{{ID: p.node}}}})
	}
	if err := stream.Send(&dp.ListAndWatchResponse{Devices: devices}); err != nil {
		return err
	}
	<-stream.Context().Done()
	return stream.Context().Err()
}
func (p *plugin) Allocate(_ context.Context, req *dp.AllocateRequest) (*dp.AllocateResponse, error) {
	reply := &dp.AllocateResponse{}
	for _, c := range req.ContainerRequests {
		for _, id := range c.DevicesIds {
			if !strings.HasPrefix(id, fmt.Sprintf("numa%d-", p.node)) {
				return nil, fmt.Errorf("wrong topology ID %s", id)
			}
		}
		reply.ContainerResponses = append(reply.ContainerResponses, &dp.ContainerAllocateResponse{Envs: map[string]string{"ALLOCATED_NUMA_DEVICES": strings.Join(c.DevicesIds, ",")}})
	}
	return reply, nil
}
func servePlugin(dir string, node int64) {
	path := filepath.Join(dir, "resource-probe.sock")
	check(os.MkdirAll(dir, 0755))
	_ = os.Remove(path)
	listener, err := net.Listen("unix", path)
	check(err)
	defer listener.Close()
	defer os.Remove(path)
	server := grpc.NewServer()
	dp.RegisterDevicePluginServer(server, &plugin{node: node})
	go func() { check(server.Serve(listener)) }()
	// Re-register after agent restart removes this socket, as required by device plugins.
	for {
		connection := connect(filepath.Join(dir, "kubelet.sock"))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := dp.NewRegistrationClient(connection).Register(ctx, &dp.RegisterRequest{Version: dp.Version, Endpoint: filepath.Base(path), ResourceName: "devices.example.test/numa"})
		cancel()
		connection.Close()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			time.Sleep(time.Second)
			continue
		}
		fmt.Println("registered")
		for {
			time.Sleep(time.Second)
			if _, err = os.Stat(path); os.IsNotExist(err) {
				break
			}
		}
		server.Stop()
		listener.Close()
		listener, err = net.Listen("unix", path)
		check(err)
		server = grpc.NewServer()
		dp.RegisterDevicePluginServer(server, &plugin{node: node})
		go func(s *grpc.Server, l net.Listener) { check(s.Serve(l)) }(server, listener)
	}
}

func report(path, namespace, name string) {
	connection := connect(path)
	defer connection.Close()
	client := pr.NewPodResourcesListerClient(connection)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	list, err := client.List(ctx, &pr.ListPodResourcesRequest{})
	check(err)
	allocatable, err := client.GetAllocatableResources(ctx, &pr.AllocatableResourcesRequest{})
	check(err)
	result := map[string]any{"list": list, "allocatable": allocatable}
	if name != "" {
		one, err := client.Get(ctx, &pr.GetPodResourcesRequest{PodNamespace: namespace, PodName: name})
		check(err)
		result["get"] = one
	}
	_, err = client.Get(ctx, &pr.GetPodResourcesRequest{PodNamespace: "default", PodName: "missing-resource-probe"})
	result["notFoundCode"] = status.Code(err).String()
	check(json.NewEncoder(os.Stdout).Encode(result))
}

func probe(path string, pages int) {
	data, err := os.ReadFile("/proc/self/status")
	check(err)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Cpus_allowed_list:") || strings.HasPrefix(line, "Mems_allowed_list:") {
			fmt.Println(line)
		}
	}
	for _, file := range []string{"cpuset.cpus.effective", "cpuset.mems.effective", "hugetlb.2MB.max"} {
		data, err := os.ReadFile(filepath.Join("/sys/fs/cgroup", file))
		if err == nil {
			fmt.Printf("%s=%s", file, data)
		}
	}
	memory, err := unix.Mmap(-1, 0, 64<<20, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON)
	check(err)
	for i := 0; i < len(memory); i += 4096 {
		memory[i] = 1
	}
	maps, err := os.ReadFile("/proc/self/numa_maps")
	check(err)
	fmt.Printf("NUMA_MAPS_BEGIN\n%sNUMA_MAPS_END\n", maps)
	if pages > 0 {
		f, err := os.OpenFile(filepath.Join(path, "probe"), os.O_CREATE|os.O_RDWR, 0600)
		check(err)
		defer f.Close()
		check(f.Truncate(int64(pages) * (2 << 20)))
		mapped, err := unix.Mmap(int(f.Fd()), 0, pages*(2<<20), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_SHARED|unix.MAP_NORESERVE)
		check(err)
		for i := 0; i < pages; i++ {
			mapped[i*(2<<20)] = 1
			fmt.Printf("hugepage-touched=%d\n", i+1)
		}
		check(unix.Munmap(mapped))
		check(os.Remove(f.Name()))
	}
	fmt.Println("RESOURCE_PROBE_OK")
	check(unix.Munmap(memory))
}

func main() {
	mode := flag.String("mode", "report", "report, plugin, or probe")
	socket := flag.String("socket", "/var/lib/kubelet/pod-resources/kubelet.sock", "PodResources socket")
	namespace := flag.String("namespace", "default", "Pod namespace")
	name := flag.String("name", "", "Pod name")
	dir := flag.String("directory", "/var/lib/kubelet/device-plugins", "plugin directory or hugetlbfs probe path")
	node := flag.Int64("node", 1, "device NUMA node")
	pages := flag.Int("pages", 0, "hugepages to fault in")
	flag.Parse()
	switch *mode {
	case "report":
		report(*socket, *namespace, *name)
	case "plugin":
		servePlugin(*dir, *node)
	case "probe":
		probe(*dir, *pages)
	default:
		panic("unknown mode")
	}
}
