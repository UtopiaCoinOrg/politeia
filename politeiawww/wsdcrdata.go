package main

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	client "github.com/UtopiaCoinOrg/ucdata/pubsub/v2/psclient"
	"github.com/UtopiaCoinOrg/ucdata/semver"
	"github.com/UtopiaCoinOrg/politeia/util"
)

const (
	// addrSubPrefix must be prefixed to the address when subscribing
	// to address events.
	addrSubPrefix = "address:"
)

var (
	// errDuplicateSub is emitted when attempting to subscribe to an
	// event that has already been subscribed to.
	errDuplicateSub = errors.New("duplicate subscription")

	// errSubNotFound is emitted when attempting to unsubscribe to an
	// event that has not yet been subscribed to.
	errSubNotFound = errors.New("subscription not found")
)

// wsUcdata is the context used for managing a ucdata websocket connection.
type wsUcdata struct {
	sync.RWMutex
	client        *client.Client      // ucdata websocket client
	subscriptions map[string]struct{} // Client subscriptions
}

// addSub adds an event subscription to the subscriptions map.
func (w *wsUcdata) addSub(event string) {
	w.Lock()
	defer w.Unlock()

	w.subscriptions[event] = struct{}{}
}

// removeSub removes an event subscription from the subscriptions map.
func (w *wsUcdata) removeSub(event string) {
	w.Lock()
	defer w.Unlock()

	delete(w.subscriptions, event)
}

// isSubscribed returns whether the client is subscribed to the provided event.
func (w *wsUcdata) isSubscribed(event string) bool {
	w.RLock()
	defer w.RUnlock()

	_, ok := w.subscriptions[event]
	return ok
}

// subToPing subscribes to the ucdata ping event.
func (w *wsUcdata) subToPing() error {
	_, err := w.client.Subscribe("ping")
	if err != nil {
		return fmt.Errorf("failed to subscribe: %v", err)
	}
	log.Debugf("wsUcdata subscribed to ping")
	return nil
}

// subToAddr subscribes to ucdata events for the provided address.
func (w *wsUcdata) subToAddr(address string) error {
	event := addrSubPrefix + address
	if w.isSubscribed(event) {
		return errDuplicateSub
	}
	_, err := w.client.Subscribe(event)
	if err != nil {
		return fmt.Errorf("failed to subscribe: %v", err)
	}
	w.addSub(event)
	log.Debugf("wsUcdata subscribed to addr: %v", address)
	return nil
}

// unsubFromAddr unsubscribes from ucdata events for the provided address.
func (w *wsUcdata) unsubFromAddr(address string) error {
	event := addrSubPrefix + address
	if !w.isSubscribed(event) {
		return errSubNotFound
	}
	_, err := w.client.Unsubscribe(event)
	if err != nil {
		return fmt.Errorf("failed to unsubscribe: %v", err)
	}
	w.removeSub(event)
	log.Debugf("wsUcdata unsubscribed from addr: %v", address)
	return nil
}

// newWSUcdata return a new wsUcdata context.
func newWSUcdata() (*wsUcdata, error) {
	// Init websocket client
	u, err := util.BlockExplorerURLForSubscriptions(activeNetParams.Params)
	if err != nil {
		return nil, err
	}
	opts := client.Opts{
		ReadTimeout:  3 * time.Second,
		WriteTimeout: 3 * time.Second,
	}
	c, err := client.New(u, context.Background(), &opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %v: %v", u, err)
	}

	log.Infof("Ucdata websocket host: %v", u)

	// Check client and server compatibility
	v, err := c.ServerVersion()
	if err != nil {
		return nil, fmt.Errorf("server version failed: %v", err)
	}
	serverSemVer := semver.NewSemver(v.Major, v.Minor, v.Patch)
	clientSemVer := client.Version()
	if !semver.Compatible(clientSemVer, serverSemVer) {
		return nil, fmt.Errorf("version mismatch; client %v, server %v",
			serverSemVer, clientSemVer)
	}

	log.Infof("Ucdata pubsub server version: %v, client version %v",
		serverSemVer, clientSemVer)

	return &wsUcdata{
		client:        c,
		subscriptions: make(map[string]struct{}),
	}, nil
}
