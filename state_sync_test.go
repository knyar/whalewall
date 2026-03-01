package whalewall

import (
	"context"
	"net/netip"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/google/nftables"
	"github.com/matryer/is"
	"go.uber.org/zap"
)

// notFoundErr implements errdefs.ErrNotFound so client.IsErrNotFound returns true.
type notFoundErr struct {
	msg string
}

func (e *notFoundErr) Error() string { return e.msg }
func (e *notFoundErr) NotFound()     {}

// syncDockerClient wraps mockDockerClient but returns a proper ErrNotFound
// error from ContainerInspect so that client.IsErrNotFound works.
type syncDockerClient struct {
	*mockDockerClient
}

func (s *syncDockerClient) ContainerInspect(ctx context.Context, containerID string) (types.ContainerJSON, error) {
	c, err := s.mockDockerClient.ContainerInspect(ctx, containerID)
	if err != nil {
		return c, &notFoundErr{msg: "container not found: " + containerID}
	}
	return c, nil
}

// setupSyncTest creates a RuleManager with mock clients, initializes the
// database and base nftables rules. It returns the RuleManager, mock docker
// client, mock firewall (for inspecting state), and a cleanup function.
func setupSyncTest(t *testing.T) (*RuleManager, *mockDockerClient, *mockFirewall) {
	t.Helper()

	is := is.New(t)
	logger, err := zap.NewDevelopment()
	is.NoErr(err)

	dbFile := filepath.Join(t.TempDir(), "db.sqlite")
	r, err := NewRuleManager(context.Background(), logger, dbFile, defaultTimeout)
	is.NoErr(err)

	dockerCli := newMockDockerClient(nil)
	r.newDockerClient = func() (dockerClient, error) {
		return &syncDockerClient{dockerCli}, nil
	}

	firewallCreator := newMockFirewallCreator(logger)
	mfc := firewallCreator.newMockFirewall()
	mfc.AddTable(filterTable)
	mfc.AddChain(&nftables.Chain{
		Name:  dockerChainName,
		Table: filterTable,
		Type:  nftables.ChainTypeFilter,
	})
	is.NoErr(mfc.Flush())
	r.newFirewallClient = func() (firewallClient, error) {
		return firewallCreator.newMockFirewall(), nil
	}

	err = r.init(context.Background())
	is.NoErr(err)
	err = r.createBaseRules()
	is.NoErr(err)
	t.Cleanup(func() {
		err := r.clearRules(context.Background())
		is.NoErr(err)
	})

	return r, dockerCli, mfc
}

func TestCleanupStaleDBEntries_RemovedContainer(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, mfc := setupSyncTest(t)

	// Create a container and its rules.
	cont := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   cont1ID,
			Name: "/" + cont1Name,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(),
				},
			},
		},
	}
	dockerCli.containers = append(dockerCli.containers, cont)
	err := r.createContainerRules(context.Background(), cont, true)
	is.NoErr(err)

	// Verify rules were created.
	chainName := buildChainName(cont1Name, cont1ID)
	chain := &nftables.Chain{Table: filterTable, Name: chainName}
	rules, err := mfc.GetRules(filterTable, chain)
	is.NoErr(err)
	is.True(len(rules) > 0) // rules were created

	// Verify container is in DB.
	exists, err := r.containerExists(context.Background(), r.db, cont1ID)
	is.NoErr(err)
	is.True(exists) // container exists in DB

	// Remove container from Docker (simulate removal).
	dockerCli.mtx.Lock()
	dockerCli.containers = nil
	dockerCli.mtx.Unlock()

	// Run cleanup.
	err = r.cleanupStaleDBEntries(context.Background())
	is.NoErr(err)

	// Verify DB entry was removed.
	exists, err = r.containerExists(context.Background(), r.db, cont1ID)
	is.NoErr(err)
	is.True(!exists) // container should be removed from DB

	// Verify nftables chain was removed.
	_, err = mfc.GetRules(filterTable, chain)
	is.True(err == syscall.ENOENT) // chain should be removed
}

func TestCleanupStaleDBEntries_StoppedContainer(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, mfc := setupSyncTest(t)

	// Create a container and its rules.
	cont := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   cont1ID,
			Name: "/" + cont1Name,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(),
				},
			},
		},
	}
	dockerCli.containers = append(dockerCli.containers, cont)
	err := r.createContainerRules(context.Background(), cont, true)
	is.NoErr(err)

	// Stop the container (keep it in Docker but not running).
	dockerCli.mtx.Lock()
	dockerCli.containers[0].ContainerJSONBase.State = &types.ContainerState{
		Running: false,
	}
	dockerCli.mtx.Unlock()

	// Run cleanup.
	err = r.cleanupStaleDBEntries(context.Background())
	is.NoErr(err)

	// Verify DB entry was removed.
	exists, err := r.containerExists(context.Background(), r.db, cont1ID)
	is.NoErr(err)
	is.True(!exists) // container should be removed from DB

	// Verify nftables chain was removed.
	chainName := buildChainName(cont1Name, cont1ID)
	chain := &nftables.Chain{Table: filterTable, Name: chainName}
	_, err = mfc.GetRules(filterTable, chain)
	is.True(err == syscall.ENOENT) // chain should be removed
}

func TestForceDeleteContainerFromDB(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, _ := setupSyncTest(t)

	// Create a container and its rules.
	cont := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   cont1ID,
			Name: "/" + cont1Name,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(),
				},
			},
		},
	}
	dockerCli.containers = append(dockerCli.containers, cont)
	err := r.createContainerRules(context.Background(), cont, true)
	is.NoErr(err)

	// Verify container exists in DB.
	exists, err := r.containerExists(context.Background(), r.db, cont1ID)
	is.NoErr(err)
	is.True(exists) // container exists in DB

	// Force delete from DB only.
	err = r.forceDeleteContainerFromDB(context.Background(), cont1ID)
	is.NoErr(err)

	// Verify DB entry was removed.
	exists, err = r.containerExists(context.Background(), r.db, cont1ID)
	is.NoErr(err)
	is.True(!exists) // container should be removed from DB
}

func TestCleanupOrphanedChains(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, mfc := setupSyncTest(t)

	// Create a container and its rules.
	cont := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   cont1ID,
			Name: "/" + cont1Name,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(),
				},
			},
		},
	}
	dockerCli.containers = append(dockerCli.containers, cont)
	err := r.createContainerRules(context.Background(), cont, true)
	is.NoErr(err)

	// Verify chain exists.
	chainName := buildChainName(cont1Name, cont1ID)
	chain := &nftables.Chain{Table: filterTable, Name: chainName}
	rules, err := mfc.GetRules(filterTable, chain)
	is.NoErr(err)
	is.True(len(rules) > 0) // chain has rules

	// Force-delete DB entry only (simulating a partial cleanup failure
	// where DB was cleaned but nftables chain remains).
	err = r.forceDeleteContainerFromDB(context.Background(), cont1ID)
	is.NoErr(err)

	// Remove container from Docker.
	dockerCli.mtx.Lock()
	dockerCli.containers = nil
	dockerCli.mtx.Unlock()

	// Chain should still exist before cleanup.
	rules, err = mfc.GetRules(filterTable, chain)
	is.NoErr(err)
	is.True(len(rules) > 0) // chain still has rules

	// Run orphaned chain cleanup.
	err = r.cleanupOrphanedChains(context.Background())
	is.NoErr(err)

	// Verify chain was removed.
	_, err = mfc.GetRules(filterTable, chain)
	is.True(err == syscall.ENOENT) // orphaned chain should be removed
}

func TestSyncStateFixesStaleAddr(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, _ := setupSyncTest(t)

	// Create container1 with an IP address.
	cont1 := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   cont1ID,
			Name: "/" + cont1Name,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(),
				},
			},
		},
	}
	dockerCli.containers = append(dockerCli.containers, cont1)
	err := r.createContainerRules(context.Background(), cont1, true)
	is.NoErr(err)

	// Remove container1 from Docker (simulate it being removed).
	dockerCli.mtx.Lock()
	dockerCli.containers = nil
	dockerCli.mtx.Unlock()

	// Create container2 with the SAME IP address but different ID.
	newContID := "new_container_ID2"
	newContName := "new_container"
	cont2 := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   newContID,
			Name: "/" + newContName,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(), // Same IP as container1!
				},
			},
		},
	}

	// Without syncState, creating rules for cont2 would fail with
	// UNIQUE constraint on addrs.addr.
	r.syncState(context.Background())

	// Verify container1's DB entry was cleaned up.
	exists, err := r.containerExists(context.Background(), r.db, cont1ID)
	is.NoErr(err)
	is.True(!exists) // old container should be removed from DB

	// Now creating rules for container2 with the same IP should succeed.
	dockerCli.mtx.Lock()
	dockerCli.containers = append(dockerCli.containers, cont2)
	dockerCli.mtx.Unlock()

	err = r.createContainerRules(context.Background(), cont2, true)
	is.NoErr(err) // should succeed now that stale addr is cleaned up

	// Verify container2 is in the DB.
	exists, err = r.containerExists(context.Background(), r.db, newContID)
	is.NoErr(err)
	is.True(exists) // new container should exist in DB
}

func TestCleanupOrphanedChains_RunningContainerNotRemoved(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, mfc := setupSyncTest(t)

	// Create a container and its rules.
	cont := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   cont1ID,
			Name: "/" + cont1Name,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(),
				},
			},
		},
	}
	dockerCli.containers = append(dockerCli.containers, cont)
	err := r.createContainerRules(context.Background(), cont, true)
	is.NoErr(err)

	chainName := buildChainName(cont1Name, cont1ID)
	chain := &nftables.Chain{Table: filterTable, Name: chainName}

	// Run orphaned chain cleanup while container is still running.
	err = r.cleanupOrphanedChains(context.Background())
	is.NoErr(err)

	// Chain should still exist since the container is running.
	rules, err := mfc.GetRules(filterTable, chain)
	is.NoErr(err)
	is.True(len(rules) > 0) // chain should NOT be removed
}

func TestSyncStateTwoContainers(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, mfc := setupSyncTest(t)

	// Create two containers.
	cont1 := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   cont1ID,
			Name: "/" + cont1Name,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont1Addr.String(),
				},
			},
		},
	}
	cont2 := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:   cont2ID,
			Name: "/" + cont2Name,
			State: &types.ContainerState{
				Running: true,
			},
		},
		Config: &container.Config{
			Labels: map[string]string{
				enabledLabel: "true",
			},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: cont2Addr.String(),
				},
			},
		},
	}

	dockerCli.containers = append(dockerCli.containers, cont1, cont2)
	err := r.createContainerRules(context.Background(), cont1, true)
	is.NoErr(err)
	err = r.createContainerRules(context.Background(), cont2, true)
	is.NoErr(err)

	// Remove only container1 from Docker.
	dockerCli.mtx.Lock()
	dockerCli.containers = []types.ContainerJSON{cont2}
	dockerCli.mtx.Unlock()

	// Run sync.
	r.syncState(context.Background())

	// Container1 should be cleaned up.
	exists, err := r.containerExists(context.Background(), r.db, cont1ID)
	is.NoErr(err)
	is.True(!exists) // container1 should be removed

	cont1ChainName := buildChainName(cont1Name, cont1ID)
	_, err = mfc.GetRules(filterTable, &nftables.Chain{Table: filterTable, Name: cont1ChainName})
	is.True(err == syscall.ENOENT) // container1 chain should be removed

	// Container2 should still be intact.
	exists, err = r.containerExists(context.Background(), r.db, cont2ID)
	is.NoErr(err)
	is.True(exists) // container2 should still exist

	cont2ChainName := buildChainName(cont2Name, cont2ID)
	rules, err := mfc.GetRules(filterTable, &nftables.Chain{Table: filterTable, Name: cont2ChainName})
	is.NoErr(err)
	is.True(len(rules) > 0) // container2 chain should still have rules

	// Verify we can still get container2's address from DB.
	addrs, err := r.db.GetContainerAddrs(context.Background(), cont2ID)
	is.NoErr(err)
	expectedAddr := ref(netip.MustParseAddr("172.0.1.3").As4())[:]
	is.True(len(addrs) == 1)
	is.True(string(addrs[0]) == string(expectedAddr)) // container2 addr should be intact
}
