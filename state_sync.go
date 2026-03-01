package whalewall

import (
	"bytes"
	"context"
	"strings"
	"syscall"
	"time"

	"github.com/docker/docker/client"
	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"go.uber.org/zap"
)

const defaultSyncInterval = 30 * time.Second

// syncState reconciles whalewall's internal state (database and nftables rules)
// with the actual running containers. It removes database entries for containers
// that no longer exist in Docker, and removes orphaned nftables chains with the
// "whalewall-" prefix that don't correspond to any running container.
func (r *RuleManager) syncState(ctx context.Context) {
	r.logger.Info("syncing state with running containers")

	if err := r.cleanupStaleDBEntries(ctx); err != nil {
		r.logger.Error("error cleaning up stale database entries", zap.Error(err))
	}

	if err := r.cleanupOrphanedChains(ctx); err != nil {
		r.logger.Error("error cleaning up orphaned nftables chains", zap.Error(err))
	}
}

// cleanupStaleDBEntries removes database entries and nftables rules for
// containers that no longer exist in Docker or are no longer running.
// Unlike cleanupRules, this function always cleans the database even if
// nftables operations fail.
func (r *RuleManager) cleanupStaleDBEntries(ctx context.Context) error {
	// Remove orphaned addrs rows whose container_id doesn't match any
	// existing container. These can accumulate from incomplete cleanup
	// or if foreign key enforcement was previously disabled.
	if n, err := r.db.DeleteOrphanedAddrs(ctx); err != nil {
		r.logger.Error("sync: error deleting orphaned addrs", zap.Error(err))
	} else if n > 0 {
		r.logger.Info("sync: deleted orphaned addr entries", zap.Int64("count", n))
	}

	containers, err := r.db.GetContainers(ctx)
	if err != nil {
		return err
	}

	for _, container := range containers {
		truncID := container.ID[:12]
		contName := stripName(container.Name)
		c, inspectErr := r.dockerCli.ContainerInspect(ctx, container.ID)

		needsCleanup := false
		if inspectErr != nil {
			if client.IsErrNotFound(inspectErr) {
				r.logger.Info("sync: found stale entry for removed container",
					zap.String("container.id", truncID),
					zap.String("container.name", contName),
				)
				needsCleanup = true
			} else {
				r.logger.Error("sync: error inspecting container",
					zap.String("container.id", truncID),
					zap.Error(inspectErr),
				)
				continue
			}
		} else if !c.State.Running {
			r.logger.Info("sync: found stale entry for stopped container",
				zap.String("container.id", truncID),
				zap.String("container.name", contName),
			)
			needsCleanup = true
		}

		if !needsCleanup {
			continue
		}

		// Attempt normal cleanup which handles both nftables and DB.
		if err := r.deleteContainerRules(ctx, container.ID, contName); err != nil {
			r.logger.Warn("sync: deleteContainerRules failed, forcing DB cleanup",
				zap.String("container.id", truncID),
				zap.String("container.name", contName),
				zap.Error(err),
			)
			// Force DB-only cleanup if the full cleanup failed. This
			// ensures stale DB entries are removed even when nftables
			// operations fail (e.g. chain doesn't exist).
			if dbErr := r.forceDeleteContainerFromDB(ctx, container.ID); dbErr != nil {
				r.logger.Error("sync: error force-deleting container from database",
					zap.String("container.id", truncID),
					zap.String("container.name", contName),
					zap.Error(dbErr),
				)
			}
		}
	}

	return nil
}

// forceDeleteContainerFromDB removes all database entries for a container
// without touching nftables. This is used as a fallback when the normal
// deleteContainerRules fails due to nftables errors. It acquires the
// container tracker lock to prevent racing with concurrent create/delete
// operations from Docker event handlers.
func (r *RuleManager) forceDeleteContainerFromDB(ctx context.Context, id string) error {
	ctx, cleanup, _ := r.containerTracker.StartDeletingContainer(ctx, id)
	if cleanup != nil {
		defer cleanup()
	}

	tx, err := r.db.Begin(ctx, r.logger)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	return r.deleteContainer(ctx, tx, id)
}

// cleanupOrphanedChains removes nftables chains with the "whalewall-" prefix
// that don't correspond to any container currently tracked in the database
// or running in Docker. This catches chains left behind due to incomplete
// cleanup from crashes or partial failures.
func (r *RuleManager) cleanupOrphanedChains(ctx context.Context) error {
	nfc, err := r.newFirewallClient()
	if err != nil {
		return err
	}

	chains, err := nfc.ListChainsOfTableFamily(nftables.TableFamilyIPv4)
	if err != nil {
		return err
	}

	for _, c := range chains {
		if c.Table.Name != filterTableName {
			continue
		}
		// Only look at container chains (whalewall-<name>-<id>), skip
		// the main "whalewall" chain itself.
		if !strings.HasPrefix(c.Name, chainPrefix) || c.Name == whalewallChainName {
			continue
		}

		rules, err := nfc.GetRules(filterTable, c)
		if err != nil {
			r.logger.Error("sync: error getting rules of chain",
				zap.String("chain.name", c.Name),
				zap.Error(err),
			)
			continue
		}

		// Find the container ID from UserData on rules in this chain.
		// The drop rule always stores the container ID as UserData.
		var containerID string
		for _, rule := range rules {
			if len(rule.UserData) > 0 {
				containerID = string(rule.UserData)
				break
			}
		}

		if containerID == "" {
			// Chain has no rules with UserData; it's a leftover.
			r.logger.Info("sync: removing orphaned chain with no container ID",
				zap.String("chain.name", c.Name),
			)
			r.removeOrphanedChain(ctx, nfc, c, rules, "", chains)
			continue
		}

		// Check if this container is still running in Docker.
		truncID := containerID
		if len(truncID) > 12 {
			truncID = truncID[:12]
		}

		cont, inspectErr := r.dockerCli.ContainerInspect(ctx, containerID)
		if inspectErr != nil && !client.IsErrNotFound(inspectErr) {
			r.logger.Error("sync: error inspecting container for orphaned chain",
				zap.String("chain.name", c.Name),
				zap.String("container.id", truncID),
				zap.Error(inspectErr),
			)
			continue
		}

		if inspectErr == nil && cont.State.Running {
			// Container is still running, chain is valid.
			continue
		}

		r.logger.Info("sync: removing orphaned chain for non-running container",
			zap.String("chain.name", c.Name),
			zap.String("container.id", truncID),
		)
		r.removeOrphanedChain(ctx, nfc, c, rules, containerID, chains)
	}

	return nil
}

// removeOrphanedChain removes an nftables chain, its rules, and all
// references to it. Before deleting the chain, it removes:
//   - rules in other chains whose verdict jumps/gotos to this chain
//   - verdict map set elements in containerAddrSet that target this chain
//   - all rules within the chain itself
//
// References are found by inspecting verdict expressions and set element
// verdicts rather than relying on UserData, so this works even when the
// container ID is unknown (e.g. the chain's rules were already deleted).
// When a container ID is known, the container tracker lock is held to
// prevent racing with concurrent Docker event handlers.
func (r *RuleManager) removeOrphanedChain(ctx context.Context, nfc firewallClient, c *nftables.Chain, rules []*nftables.Rule, containerID string, allChains []*nftables.Chain) {
	// Acquire the container tracker lock if we know the container ID,
	// so we don't race with event-driven create/delete for the same container.
	if containerID != "" {
		var cleanup func()
		ctx, cleanup, _ = r.containerTracker.StartDeletingContainer(ctx, containerID)
		if cleanup != nil {
			defer cleanup()
		}
	}

	// Delete all rules in other chains that jump/goto to the chain we
	// are about to delete. This covers both:
	//   - jump rules in the main whalewall chain
	//   - "established connection" rules in other container chains
	// We match by verdict target chain name rather than UserData so
	// this works even when the containerID is unknown.
	for _, other := range allChains {
		if other.Table.Name != filterTableName || other.Name == c.Name {
			continue
		}
		otherRules, err := nfc.GetRules(filterTable, other)
		if err != nil {
			continue
		}
		deleteRulesJumpingToChain(r.logger, nfc, otherRules, c.Name)
	}

	// Remove verdict map set elements that jump to this chain. The
	// containerAddrSet is a verdict map: IP → jump(container-chain).
	// These set elements hold a reference to the chain, so the chain
	// cannot be deleted while they exist (nftables returns EBUSY).
	//
	// Note: GetSetElements returns VerdictData as nil; the nftables
	// library stores the raw verdict data in Val instead. We match
	// by checking if the chain name appears in the raw verdict bytes.
	elements, err := nfc.GetSetElements(containerAddrSet)
	if err == nil {
		chainNameBytes := []byte(c.Name)
		for _, elem := range elements {
			if bytes.Contains(elem.Val, chainNameBytes) {
				if err := nfc.SetDeleteElements(containerAddrSet, []nftables.SetElement{{Key: elem.Key}}); err != nil {
					r.logger.Error("sync: error queuing set element deletion",
						zap.String("chain.name", c.Name),
						zap.Error(err),
					)
					continue
				}
				if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
					r.logger.Error("sync: error deleting set element for orphaned chain",
						zap.String("chain.name", c.Name),
						zap.Error(err),
					)
				}
			}
		}
	}

	// Delete all rules from the orphaned chain (required before chain deletion).
	for _, rule := range rules {
		if err := nfc.DelRule(rule); err != nil {
			r.logger.Error("sync: error deleting rule from orphaned chain",
				zap.String("chain.name", c.Name),
				zap.Error(err),
			)
			continue
		}
		if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
			r.logger.Error("sync: error flushing rule deletion",
				zap.String("chain.name", c.Name),
				zap.Error(err),
			)
		}
	}

	// Delete the chain itself.
	nfc.DelChain(c)
	if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
		r.logger.Error("sync: error deleting orphaned chain",
			zap.String("chain.name", c.Name),
			zap.Error(err),
		)
	}
}

// deleteRulesJumpingToChain removes rules that have a verdict jumping or
// going to the specified chain. Unlike deleteRulesFromContainer which
// matches by UserData, this matches by inspecting the verdict expression
// in each rule, so it works even when the container ID is unknown.
func deleteRulesJumpingToChain(logger *zap.Logger, nfc firewallClient, rules []*nftables.Rule, chainName string) {
	for _, rule := range rules {
		for _, e := range rule.Exprs {
			verdict, ok := e.(*expr.Verdict)
			if !ok {
				continue
			}
			if (verdict.Kind == expr.VerdictJump || verdict.Kind == expr.VerdictGoto) && verdict.Chain == chainName {
				if err := nfc.DelRule(rule); err != nil {
					logger.Error("sync: error deleting rule jumping to chain",
						zap.String("target.chain", chainName),
						zap.Error(err),
					)
					break
				}
				if err := ignoringErr(nfc.Flush, syscall.ENOENT); err != nil {
					logger.Error("sync: error flushing rule deletion",
						zap.String("target.chain", chainName),
						zap.Error(err),
					)
				}
				break
			}
		}
	}
}

// startPeriodicSync runs syncState periodically until the manager is stopped.
func (r *RuleManager) startPeriodicSync(ctx context.Context) {
	ticker := time.NewTicker(defaultSyncInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			r.syncState(ctx)
			// After cleaning up stale state, re-sync containers to
			// recreate rules for any running containers that may have
			// been affected.
			if err := r.syncContainers(ctx); err != nil {
				r.logger.Error("error syncing containers after state sync", zap.Error(err))
			}
		case <-r.stopping:
			return
		}
	}
}
