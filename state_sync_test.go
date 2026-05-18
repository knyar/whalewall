package whalewall

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
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
	is.True(errors.Is(err, syscall.ENOENT)) // chain should be removed
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
	is.True(errors.Is(err, syscall.ENOENT)) // chain should be removed
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
	is.True(errors.Is(err, syscall.ENOENT)) // orphaned chain should be removed
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
	is.True(errors.Is(err, syscall.ENOENT)) // container1 chain should be removed

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

// containsAddr returns true if the addr is present as the key of any
// element in elements.
func containsAddr(elements []nftables.SetElement, addr netip.Addr) bool {
	key := ref(addr.As4())[:]
	for _, e := range elements {
		if bytes.Equal(e.Key, key) {
			return true
		}
	}
	return false
}

// TestStaleAddrCleanedOnIPChange exercises the bug from the field
// report: a container kept its ID but Docker reassigned its IP. The
// map should end up with only the current IP after a re-sync, and the
// DB should reflect the same.
func TestStaleAddrCleanedOnIPChange(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, _ := setupSyncTest(t)

	oldAddr := cont1Addr
	newAddr := netip.MustParseAddr("172.0.1.42")

	cont := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:    cont1ID,
			Name:  "/" + cont1Name,
			State: &types.ContainerState{Running: true},
		},
		Config: &container.Config{
			Labels: map[string]string{enabledLabel: "true"},
		},
		NetworkSettings: &types.NetworkSettings{
			Networks: map[string]*network.EndpointSettings{
				"default": {
					Gateway:   gatewayAddr.String(),
					IPAddress: oldAddr.String(),
				},
			},
		},
	}
	dockerCli.containers = append(dockerCli.containers, cont)
	err := r.createContainerRules(context.Background(), cont, true)
	is.NoErr(err)

	// Sanity check: old addr tracked in DB and in map.
	tracked, err := r.db.GetContainerAddrs(context.Background(), cont1ID)
	is.NoErr(err)
	is.True(len(tracked) == 1)
	is.True(bytes.Equal(tracked[0], ref(oldAddr.As4())[:]))

	nfc, err := r.newFirewallClient()
	is.NoErr(err)
	elements, err := nfc.GetSetElements(containerAddrSet)
	is.NoErr(err)
	is.True(containsAddr(elements, oldAddr))

	// Docker reassigns the IP (e.g. after a restart) but keeps the
	// container ID the same. The next sync iteration will invoke
	// createContainerRules with isNew=false.
	dockerCli.mtx.Lock()
	dockerCli.containers[0].NetworkSettings.Networks["default"].IPAddress = newAddr.String()
	dockerCli.mtx.Unlock()

	updated := dockerCli.containers[0]
	err = r.createContainerRules(context.Background(), updated, false)
	is.NoErr(err)

	// DB should now track only the new addr.
	tracked, err = r.db.GetContainerAddrs(context.Background(), cont1ID)
	is.NoErr(err)
	is.True(len(tracked) == 1)
	is.True(bytes.Equal(tracked[0], ref(newAddr.As4())[:]))

	// Map should have the new addr and not the old one.
	nfc, err = r.newFirewallClient()
	is.NoErr(err)
	elements, err = nfc.GetSetElements(containerAddrSet)
	is.NoErr(err)
	is.True(containsAddr(elements, newAddr))
	is.True(!containsAddr(elements, oldAddr))
}

// TestCleanupOrphanedMapEntries verifies the periodic-sync safety net:
// map entries whose IP isn't tracked by any container in the DB get
// removed, while legitimate entries are left alone.
func TestCleanupOrphanedMapEntries(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, _ := setupSyncTest(t)

	// One real container — its addr should survive the sweep.
	cont := types.ContainerJSON{
		ContainerJSONBase: &types.ContainerJSONBase{
			ID:    cont1ID,
			Name:  "/" + cont1Name,
			State: &types.ContainerState{Running: true},
		},
		Config: &container.Config{
			Labels: map[string]string{enabledLabel: "true"},
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

	// Inject an orphan map entry directly: this simulates state left
	// behind by a crash, an upgrade, or any code path that bypassed
	// the per-container reconciliation. Use a fresh firewall client
	// so its local clone has the containerAddrSet that was created
	// by createBaseRules.
	orphanAddr := netip.MustParseAddr("172.0.1.123")
	injector, err := r.newFirewallClient()
	is.NoErr(err)
	err = injector.SetAddElements(containerAddrSet, []nftables.SetElement{
		{
			Key: ref(orphanAddr.As4())[:],
			VerdictData: &expr.Verdict{
				Kind:  expr.VerdictJump,
				Chain: "whalewall-some-removed-chain",
			},
		},
	})
	is.NoErr(err)
	is.NoErr(injector.Flush())

	// Both should now be present in the map.
	nfc, err := r.newFirewallClient()
	is.NoErr(err)
	elements, err := nfc.GetSetElements(containerAddrSet)
	is.NoErr(err)
	is.True(containsAddr(elements, cont1Addr))
	is.True(containsAddr(elements, orphanAddr))

	err = r.cleanupOrphanedMapEntries(context.Background())
	is.NoErr(err)

	// Orphan gone, legitimate entry untouched.
	nfc, err = r.newFirewallClient()
	is.NoErr(err)
	elements, err = nfc.GetSetElements(containerAddrSet)
	is.NoErr(err)
	is.True(containsAddr(elements, cont1Addr))
	is.True(!containsAddr(elements, orphanAddr))
}

// TestContainerNameMatches_ProjectScoping covers the cross-project
// guard: when matching by Docker Compose service name, the src and
// target must share a project. Exact-name matches still work across
// projects, and the absence of project info preserves the original
// permissive behavior.
func TestContainerNameMatches_ProjectScoping(t *testing.T) {
	t.Parallel()

	is := is.New(t)

	// Service-name match in a different project: rejected.
	is.True(!containerNameMatches(
		"redis-1", "projectA",
		map[string]string{
			composeServiceLabel: "redis-1",
			composeProjectLabel: "projectB",
		},
		"/projectB-redis-1",
	))

	// Service-name match in the same project: accepted.
	is.True(containerNameMatches(
		"redis-1", "projectA",
		map[string]string{
			composeServiceLabel: "redis-1",
			composeProjectLabel: "projectA",
		},
		"/projectA-redis-1",
	))

	// Exact name match: project info is irrelevant.
	is.True(containerNameMatches(
		"/projectB-redis-1", "projectA",
		map[string]string{
			composeServiceLabel: "redis-1",
			composeProjectLabel: "projectB",
		},
		"/projectB-redis-1",
	))

	// No src project (e.g. non-compose deployment): still accept the
	// service-name match.
	is.True(containerNameMatches(
		"redis-1", "",
		map[string]string{composeServiceLabel: "redis-1"},
		"/redis-1",
	))

	// No target project: also accept.
	is.True(containerNameMatches(
		"redis-1", "projectA",
		map[string]string{composeServiceLabel: "redis-1"},
		"/redis-1",
	))
}
