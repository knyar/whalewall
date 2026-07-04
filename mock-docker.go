package whalewall

import (
	"context"
	"errors"
	"slices"
	"sync"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
)

type dockerClient interface {
	Ping(ctx context.Context) (types.Ping, error)
	Events(ctx context.Context, options types.EventsOptions) (<-chan events.Message, <-chan error)
	ContainerList(ctx context.Context, options types.ContainerListOptions) ([]types.Container, error)
	ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error)
	Close() error
}

type mockDockerClient struct {
	mtx sync.RWMutex

	eventCh     chan events.Message
	streamErrCh chan error
	pingErr     error
	containers  []types.ContainerJSON
}

func newMockDockerClient(containers []types.ContainerJSON) *mockDockerClient {
	return &mockDockerClient{
		eventCh:     make(chan events.Message),
		streamErrCh: make(chan error),
		containers:  containers,
	}
}

func (m *mockDockerClient) setPingErr(err error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	m.pingErr = err
}

func (m *mockDockerClient) Ping(_ context.Context) (types.Ping, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	return types.Ping{}, m.pingErr
}

func (m *mockDockerClient) Events(_ context.Context, _ types.EventsOptions) (<-chan events.Message, <-chan error) {
	return m.eventCh, m.streamErrCh
}

func (m *mockDockerClient) ContainerList(_ context.Context, _ types.ContainerListOptions) ([]types.Container, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	listedConts := make([]types.Container, len(m.containers))
	for i, cont := range m.containers {
		listedConts[i] = types.Container{
			ID:     cont.ID,
			Names:  []string{cont.Name},
			Labels: cont.Config.Labels,
		}
	}

	return listedConts, nil
}

func (m *mockDockerClient) ContainerInspect(_ context.Context, containerID string) (types.ContainerJSON, error) {
	m.mtx.RLock()
	defer m.mtx.RUnlock()

	i := slices.IndexFunc(m.containers, func(c types.ContainerJSON) bool {
		return c.ID == containerID
	})
	if i == -1 {
		return types.ContainerJSON{}, errors.New("container not found")
	}

	return m.containers[i], nil
}

func (m *mockDockerClient) Close() error {
	return nil
}
