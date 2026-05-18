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
	dockerCli.containers[0].State = &types.ContainerState{
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
// guard. The cross-project guard is asymmetric on the source: a
// non-compose source (no project label) is allowed to match any
// service name; a compose source must share its project with the
// target. A target with a service label but no project label is
// treated as suspect and rejected when the source has a project.
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
	// service-name match against any target.
	is.True(containerNameMatches(
		"redis-1", "",
		map[string]string{composeServiceLabel: "redis-1"},
		"/redis-1",
	))

	// Src has a project but the target has only a service label
	// (no project): rejected. A bare service label without a paired
	// project is not normal Docker Compose output and should not be
	// matched cross-project. The target's container name doesn't
	// match expectedName, so the check falls through to the
	// service-label path.
	is.True(!containerNameMatches(
		"redis-1", "projectA",
		map[string]string{composeServiceLabel: "redis-1"},
		"/manually-started-redis",
	))
}

// TestSweepDoesNotDeleteFreshlyCreatedAddrs verifies the invariant
// the orphan sweep relies on: createContainerRules installs a
// container's map entries only after its DB transaction has committed.
// We exercise this by running the full sweep immediately after
// createContainerRules returns; if the ordering were wrong, the sweep
// could observe the new map entry before its DB row landed and delete
// it as orphaned.
func TestSweepDoesNotDeleteFreshlyCreatedAddrs(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, _ := setupSyncTest(t)

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

	// Run the orphan sweep right after creation: under the
	// DB-then-map ordering invariant, the addr is in both the DB
	// and the map, so the sweep must leave it alone.
	err = r.cleanupOrphanedMapEntries(context.Background())
	is.NoErr(err)

	nfc, err := r.newFirewallClient()
	is.NoErr(err)
	elements, err := nfc.GetSetElements(containerAddrSet)
	is.NoErr(err)
	is.True(containsAddr(elements, cont1Addr)) // addr should survive the sweep

	// And the DB should still know about it.
	tracked, err := r.db.GetContainerAddrs(context.Background(), cont1ID)
	is.NoErr(err)
	is.True(len(tracked) == 1)
	is.True(bytes.Equal(tracked[0], ref(cont1Addr.As4())[:]))
}

// TestStaleAddrFlushedFromMapAfterCommit verifies that the stale-addr
// removal also runs after the DB tx commits. We seed an isNew=true
// container, simulate Docker reassigning its IP, re-process, and check
// that both the map and DB only reflect the new IP — and that the
// orphan sweep is consistent with the per-container reconciliation.
func TestStaleAddrFlushedFromMapAfterCommit(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, _ := setupSyncTest(t)

	oldAddr := cont1Addr
	newAddr := netip.MustParseAddr("172.0.1.77")

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
	is.NoErr(r.createContainerRules(context.Background(), cont, true))

	dockerCli.mtx.Lock()
	dockerCli.containers[0].NetworkSettings.Networks["default"].IPAddress = newAddr.String()
	dockerCli.mtx.Unlock()

	updated := dockerCli.containers[0]
	is.NoErr(r.createContainerRules(context.Background(), updated, false))

	// Run the orphan sweep — old addr is no longer in DB after the
	// reconciliation in createContainerRules, but we also removed
	// it from the map in the same post-commit step, so the sweep
	// has nothing to clean up.
	is.NoErr(r.cleanupOrphanedMapEntries(context.Background()))

	nfc, err := r.newFirewallClient()
	is.NoErr(err)
	elements, err := nfc.GetSetElements(containerAddrSet)
	is.NoErr(err)
	is.True(containsAddr(elements, newAddr))
	is.True(!containsAddr(elements, oldAddr))
}

// TestCrossProjectWaitingRuleFiltered reproduces the field-report
// scenario: two compose projects (prod and dev) each have a server
// that references "container: redis-1" and a redis-1 service. Without
// the cross-project filter, prod-server's "redis-1" rule attracts a
// match against dev-redis (and vice versa), creating a flapping
// rule in each project's redis chain that the cleanup pass logs as
// "deleting rule not created by whalewall" every sync interval.
//
// With the filter in place, each server's rule should only ever land
// in its own project's redis chain.
func TestCrossProjectWaitingRuleFiltered(t *testing.T) {
	t.Parallel()

	is := is.New(t)
	r, dockerCli, _ := setupSyncTest(t)

	// Helper to build a container with compose labels.
	makeCompose := func(id, name, project, service, networkName string, addr netip.Addr, rules string) types.ContainerJSON {
		labels := map[string]string{
			enabledLabel:        "true",
			composeProjectLabel: project,
			composeServiceLabel: service,
		}
		if rules != "" {
			labels[rulesLabel] = rules
		}
		return types.ContainerJSON{
			ContainerJSONBase: &types.ContainerJSONBase{
				ID:    id,
				Name:  "/" + name,
				State: &types.ContainerState{Running: true},
			},
			Config: &container.Config{Labels: labels},
			NetworkSettings: &types.NetworkSettings{
				Networks: map[string]*network.EndpointSettings{
					networkName: {
						Gateway:   gatewayAddr.String(),
						IPAddress: addr.String(),
					},
				},
			},
		}
	}

	// Compose names networks as "${project}_${network}", so a rule
	// that references `network: default` resolves against either
	// "default" or "${project}_default". The lookup is by entry in
	// the container's NetworkSettings.Networks map.
	const (
		prodNet = "svitle-api_default"
		devNet  = "svitle-api-dev_default"
	)
	prodRedisAddr := netip.MustParseAddr("172.20.0.2")
	prodServerAddr := netip.MustParseAddr("172.20.0.3")
	devRedisAddr := netip.MustParseAddr("172.19.0.2")
	devServerAddr := netip.MustParseAddr("172.19.0.3")

	// Each "server" container references "container: redis-1" by
	// service name — the exact pattern that triggered the bug.
	serverRules := `
output:
  - network: default
    container: redis-1
    proto: tcp
    dst_ports:
      - 6379`
	prodRedis := makeCompose("prod_redis_id", "svitle-api-redis-1", "svitle-api", "redis-1", prodNet, prodRedisAddr, "")
	prodServer := makeCompose("prod_server_id", "svitle-api-server-1", "svitle-api", "server", prodNet, prodServerAddr, serverRules)
	devRedis := makeCompose("dev_redis_id", "svitle-api-dev-redis-1", "svitle-api-dev", "redis-1", devNet, devRedisAddr, "")
	devServer := makeCompose("dev_server_id", "svitle-api-dev-server-1", "svitle-api-dev", "server", devNet, devServerAddr, serverRules)

	dockerCli.containers = append(dockerCli.containers, prodRedis, prodServer, devRedis, devServer)
	for _, c := range []types.ContainerJSON{prodRedis, prodServer, devRedis, devServer} {
		is.NoErr(r.createContainerRules(context.Background(), c, true))
	}

	// Run a periodic re-sync — this is what was logging the warning
	// in the field, because each pass would observe cross-project
	// rules left over from the previous pass and delete them, only
	// for the next pass to re-add them.
	for _, c := range []types.ContainerJSON{prodRedis, prodServer, devRedis, devServer} {
		is.NoErr(r.createContainerRules(context.Background(), c, false))
	}

	// prod-server's chain should reach prod-redis only.
	prodServerChain := &nftables.Chain{
		Table: filterTable,
		Name:  buildChainName("svitle-api-server-1", "prod_server_id"),
	}
	nfc, err := r.newFirewallClient()
	is.NoErr(err)
	prodServerRules, err := nfc.GetRules(filterTable, prodServerChain)
	is.NoErr(err)
	assertRuleDoesNotMatchAddr(t, prodServerRules, devRedisAddr)

	// dev-server's chain should reach dev-redis only.
	devServerChain := &nftables.Chain{
		Table: filterTable,
		Name:  buildChainName("svitle-api-dev-server-1", "dev_server_id"),
	}
	devServerRules, err := nfc.GetRules(filterTable, devServerChain)
	is.NoErr(err)
	assertRuleDoesNotMatchAddr(t, devServerRules, prodRedisAddr)

	// prod-redis's chain shouldn't carry an est rule for dev-server.
	prodRedisChain := &nftables.Chain{
		Table: filterTable,
		Name:  buildChainName("svitle-api-redis-1", "prod_redis_id"),
	}
	prodRedisRules, err := nfc.GetRules(filterTable, prodRedisChain)
	is.NoErr(err)
	assertRuleDoesNotMatchAddr(t, prodRedisRules, devServerAddr)

	// dev-redis's chain shouldn't carry an est rule for prod-server.
	devRedisChain := &nftables.Chain{
		Table: filterTable,
		Name:  buildChainName("svitle-api-dev-redis-1", "dev_redis_id"),
	}
	devRedisRules, err := nfc.GetRules(filterTable, devRedisChain)
	is.NoErr(err)
	assertRuleDoesNotMatchAddr(t, devRedisRules, prodServerAddr)
}

// assertRuleDoesNotMatchAddr fails the test if any rule in the slice
// references the given addr in its saddr or daddr comparison. Used
// to assert that cross-project rules didn't leak into a chain.
func assertRuleDoesNotMatchAddr(t *testing.T, rules []*nftables.Rule, addr netip.Addr) {
	t.Helper()
	target := ref(addr.As4())[:]
	for i, rule := range rules {
		for _, e := range rule.Exprs {
			cmp, ok := e.(*expr.Cmp)
			if !ok {
				continue
			}
			if bytes.Equal(cmp.Data, target) {
				t.Errorf("rule %d unexpectedly references %s: %+v", i, addr, rule)
			}
		}
	}
}
