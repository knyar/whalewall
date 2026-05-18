package whalewall

import (
	"context"
	"fmt"

	"github.com/capnspacehook/whalewall/database"
)

// TODO: use 'go run' when https://github.com/golang/go/issues/33468 is fixed
// or use 'go tool' instead if https://github.com/golang/go/issues/48429 is implemented
//go:generate go install github.com/sqlc-dev/sqlc/cmd/sqlc@v1.20.0
//go:generate sqlc generate

func (r *RuleManager) containerExists(ctx context.Context, db database.Querier, id string) (bool, error) {
	exists, err := db.ContainerExists(ctx, id)
	if err != nil {
		return false, err
	}
	return exists == 1, nil
}

// syncContainerAddrs reconciles the DB-tracked addrs for a container
// with the given set. When hasStale is true (the caller's prior read
// turned up rows that are no longer in the current set), all
// existing rows for the container are deleted first; otherwise only
// INSERT OR REPLACE is issued for the current addrs. Skipping the
// delete in the common case keeps the transaction's SQLite write-
// lock window short, which reduces contention against concurrent
// deleteContainerRules / clearRules calls that happen in tests.
func syncContainerAddrs(ctx context.Context, tx database.TX, id string, addrs map[string][]byte, hasStale bool) error {
	if hasStale {
		if err := tx.DeleteContainerAddrs(ctx, id); err != nil {
			return fmt.Errorf("error deleting container addrs from database: %w", err)
		}
	}
	for _, addr := range addrs {
		if err := tx.AddContainerAddr(ctx, addr, id); err != nil {
			return fmt.Errorf("error adding container addr to database: %w", err)
		}
	}
	return nil
}

// addContainerInfo records container aliases and established-container
// references, then commits the transaction. Only called for newly
// created containers; addr reconciliation is handled separately by
// syncContainerAddrs so it runs on every rule creation.
func (r *RuleManager) addContainerInfo(ctx context.Context, tx database.TX, id, name, service string, estContainers map[string]struct{}) error {
	// add names the container may have been referred to in user rules
	// so when creating rules that specify this container it can be found
	aliases := containerAliases(name, service)
	for _, alias := range aliases {
		err := tx.AddContainerAlias(ctx, id, alias)
		if err != nil {
			return fmt.Errorf("error adding container alias to database: %w", err)
		}
	}

	// keep track if rules were put into other container's chains so
	// they can be cleaned up when this container is stopped
	for estContainer := range estContainers {
		err := tx.AddEstContainer(ctx, id, estContainer)
		if err != nil {
			return fmt.Errorf("error adding established container to database: %w", err)
		}
	}

	return tx.Commit()
}

func containerAliases(name, service string) []string {
	aliases := []string{"/" + name}
	if service != "" && service != name {
		aliases = append(aliases, service)
		aliases = append(aliases, "/"+service)
	}
	return aliases
}

func (r *RuleManager) deleteContainer(ctx context.Context, tx database.TX, id string) error {
	if err := tx.DeleteContainerAddrs(ctx, id); err != nil {
		return fmt.Errorf("error deleting container addrs in database: %w", err)
	}
	if err := tx.DeleteContainerAliases(ctx, id); err != nil {
		return fmt.Errorf("error deleting container aliases in database: %w", err)
	}
	if err := tx.DeleteEstContainers(ctx, id, id); err != nil {
		return fmt.Errorf("error deleting established container in database: %w", err)
	}
	// delete waiting container rules that this container created
	if err := tx.DeleteWaitingContainerRules(ctx, id); err != nil {
		return fmt.Errorf("error deleting waiting container rules in database: %w", err)
	}
	if err := tx.DeleteContainer(ctx, id); err != nil {
		return fmt.Errorf("error deleting container in database: %w", err)
	}

	return tx.Commit()
}
