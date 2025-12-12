package app

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/bepass-org/vwarp/masque"
	"github.com/bepass-org/vwarp/wireguard/tun"
	"github.com/bepass-org/vwarp/wireguard/tun/netstack"
)

// min returns the smaller of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// netstackTunAdapter wraps a tun.Device to provide packet forwarding interface
type netstackTunAdapter struct {
	dev             tun.Device
	tunnelBufPool   *sync.Pool
	tunnelSizesPool *sync.Pool
}

func (n *netstackTunAdapter) ReadPacket(buf []byte) (int, error) {
	packetBufsPtr := n.tunnelBufPool.Get().(*[][]byte)
	sizesPtr := n.tunnelSizesPool.Get().(*[]int)

	defer func() {
		(*packetBufsPtr)[0] = nil
		n.tunnelBufPool.Put(packetBufsPtr)
		n.tunnelSizesPool.Put(sizesPtr)
	}()

	(*packetBufsPtr)[0] = buf
	(*sizesPtr)[0] = 0

	_, err := n.dev.Read(*packetBufsPtr, *sizesPtr, 0)
	if err != nil {
		return 0, err
	}

	return (*sizesPtr)[0], nil
}

func (n *netstackTunAdapter) WritePacket(pkt []byte) error {
	_, err := n.dev.Write([][]byte{pkt}, 0)
	return err
}

// isConnectionError checks if the error indicates a closed or broken connection
// Enhanced for Android compatibility and mobile network conditions
func isConnectionError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())

	// Standard network connection errors
	connectionErrors := []string{
		"use of closed network connection",
		"connection reset by peer",
		"broken pipe",
		"network is unreachable",
		"no route to host",
		"connection refused",
		"connection timed out",
		"i/o timeout",
		"context deadline exceeded",
		"context canceled",
		"connection aborted",
		"transport endpoint is not connected",
		"socket is not connected",
		"network interface is down",
	}

	// Android-specific errors
	androidErrors := []string{
		"permission denied", // Android network permission issues
		"operation not permitted",
		"protocol not available",
		"address family not supported",
		"network protocol is not available",
	}

	// Check all error patterns
	allErrors := append(connectionErrors, androidErrors...)
	for _, pattern := range allErrors {
		if strings.Contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// AdapterFactory is a function that creates a new MASQUE adapter
type AdapterFactory func() (*masque.MasqueAdapter, error)

// Connection monitoring constants
const (
	HealthCheckInterval      = 30 * time.Second
	StaleConnectionThreshold = 60 * time.Second
	RecoveryCooldownPeriod   = 30 * time.Second
	MaxRecoveryAttempts      = 10
	MaxReconnectionAttempts  = 8
	ConnectivityTestTimeout  = 15 * time.Second
)

// maintainMasqueTunnel continuously forwards packets between the TUN device and MASQUE
// with automatic reconnection on connection failures
func maintainMasqueTunnel(ctx context.Context, l *slog.Logger, adapter *masque.MasqueAdapter, factory AdapterFactory, device *netstackTunAdapter, mtu int, tnet *netstack.Net, testURL string) {
	l.Info("Starting MASQUE tunnel packet forwarding with auto-reconnect")

	// Connection state management - buffered channel to prevent blocking
	connectionDown := make(chan bool, 1)

	// Track connection state with enhanced monitoring
	var connectionBroken atomic.Bool
	var lastSuccessfulRead atomic.Int64
	var lastSuccessfulWrite atomic.Int64
	var lastRecoveryTime atomic.Int64
	var adapterMutex sync.RWMutex // Protect adapter access during replacement

	// Initialize timestamps
	lastSuccessfulRead.Store(time.Now().Unix())
	lastSuccessfulWrite.Store(time.Now().Unix())

	// Forward packets from netstack to MASQUE with enhanced error handling
	go func() {
		buf := make([]byte, mtu)
		packetCount := 0
		writeErrors := 0

		for ctx.Err() == nil {
			// Wait if connection is broken
			if connectionBroken.Load() {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			n, err := device.ReadPacket(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				l.Error("error reading from TUN device", "error", err)
				// Brief pause to avoid tight loop on TUN errors
				time.Sleep(50 * time.Millisecond)
				continue
			}

			packetCount++
			if packetCount <= 5 || packetCount%100 == 0 {
				l.Debug("TX netstack→MASQUE", "packet", packetCount, "bytes", n)
			}

			// Protected adapter access
			adapterMutex.RLock()
			currentAdapter := adapter
			adapterMutex.RUnlock()

			// Write packet to MASQUE and handle ICMP response
			icmp, err := currentAdapter.WriteWithICMP(buf[:n])
			if err != nil {
				if isConnectionError(err) {
					writeErrors++
					if !connectionBroken.Load() {
						l.Warn("MASQUE connection error detected on write", "error", err, "consecutive_errors", writeErrors)
						connectionBroken.Store(true)
						// Signal connection down (non-blocking)
						select {
						case connectionDown <- true:
						default:
						}
					}
					// Exponential backoff on Android to avoid overwhelming the system
					backoffTime := time.Duration(min(writeErrors, 10)) * 100 * time.Millisecond
					time.Sleep(backoffTime)
				} else {
					l.Error("error writing to MASQUE", "error", err, "packet_size", n)
					time.Sleep(10 * time.Millisecond) // Brief pause for non-connection errors
				}
				continue
			}

			// Reset error counter on successful write
			if writeErrors > 0 {
				writeErrors = 0
				l.Debug("Write errors cleared after successful packet")
			}
			lastSuccessfulWrite.Store(time.Now().Unix())

			// Handle ICMP response if present
			if len(icmp) > 0 {
				l.Debug("received ICMP response", "size", len(icmp))
				if err := device.WritePacket(icmp); err != nil {
					l.Error("error writing ICMP to TUN device", "error", err)
				}
			}
		}
	}()

	// Forward packets from MASQUE to netstack with enhanced monitoring
	go func() {
		buf := make([]byte, mtu)
		packetCount := 0
		consecutiveErrors := 0
		readTimeouts := 0

		for ctx.Err() == nil {
			// Wait if connection is broken
			if connectionBroken.Load() {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Protected adapter access
			adapterMutex.RLock()
			currentAdapter := adapter
			adapterMutex.RUnlock()

			n, err := currentAdapter.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}

				if isConnectionError(err) {
					consecutiveErrors++

					// Categorize error types for better handling
					errStr := err.Error()
					isTimeout := strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline")

					if isTimeout {
						readTimeouts++
						l.Debug("Read timeout detected", "consecutive_timeouts", readTimeouts, "total_errors", consecutiveErrors)
					}

					if consecutiveErrors == 1 && !connectionBroken.Load() {
						l.Warn("MASQUE connection error detected on read", "error", err, "is_timeout", isTimeout)
						connectionBroken.Store(true)
						// Signal connection down (non-blocking)
						select {
						case connectionDown <- true:
						default:
						}
					}

					// Adaptive backoff based on error type and Android conditions
					if isTimeout && readTimeouts < 3 {
						// Short backoff for timeouts - may be temporary
						time.Sleep(200 * time.Millisecond)
					} else {
						// Longer backoff for connection errors or repeated timeouts
						backoffTime := time.Duration(min(consecutiveErrors, 20)) * 250 * time.Millisecond
						time.Sleep(backoffTime)
					}
				} else {
					l.Error("error reading from MASQUE", "error", err)
					consecutiveErrors++
					if consecutiveErrors > 10 {
						time.Sleep(500 * time.Millisecond)
					}
				}
				continue
			}

			// Reset error counters on successful read
			if consecutiveErrors > 0 || readTimeouts > 0 {
				l.Debug("Read errors cleared after successful packet", "prev_errors", consecutiveErrors, "prev_timeouts", readTimeouts)
				consecutiveErrors = 0
				readTimeouts = 0
			}
			lastSuccessfulRead.Store(time.Now().Unix())

			packetCount++
			if packetCount <= 5 || packetCount%100 == 0 {
				l.Debug("RX MASQUE→netstack", "packet", packetCount, "bytes", n)
			}

			if err := device.WritePacket(buf[:n]); err != nil {
				l.Error("error writing to TUN device", "error", err, "packet_size", n)
				// Brief pause to avoid flooding TUN device with failed writes
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	// Connection health monitoring goroutine
	go func() {
		healthTicker := time.NewTicker(HealthCheckInterval)
		defer healthTicker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-healthTicker.C:
				// Check if we haven't had successful reads/writes recently
				now := time.Now().Unix()
				lastRead := lastSuccessfulRead.Load()
				lastWrite := lastSuccessfulWrite.Load()

				// If no activity for too long and not already broken, trigger health check
				// But skip if we just completed recovery recently (30 second cooldown)
				lastRecovery := lastRecoveryTime.Load()
				recoveryCooldown := now-lastRecovery < int64(RecoveryCooldownPeriod.Seconds())

				if !connectionBroken.Load() && !recoveryCooldown && (now-lastRead > int64(StaleConnectionThreshold.Seconds()) || now-lastWrite > int64(StaleConnectionThreshold.Seconds())) {
					l.Warn("Connection appears stale, triggering health check",
						"seconds_since_read", now-lastRead,
						"seconds_since_write", now-lastWrite)

					// Signal connection down for investigation
					select {
					case connectionDown <- true:
					default:
					}
				} else if recoveryCooldown {
					// Skip health check during recovery cooldown period
				}
			}
		}
	}()

	// Connection monitoring and recovery goroutine - enhanced for Android
	go func() {
		recoveryAttempts := 0

		for {
			select {
			case <-ctx.Done():
				return
			case <-connectionDown:
				l.Warn("MASQUE connection lost, starting recovery process...")

				// Give time for error messages to settle and avoid rapid reconnection
				settleTime := time.Duration(min(recoveryAttempts+1, 5)) * time.Second
				time.Sleep(settleTime)

				// Try to reconnect with exponential backoff - extended for Android
				successfulRecovery := false
				for attempt := 1; attempt <= MaxReconnectionAttempts && ctx.Err() == nil; attempt++ {
					// Progressive backoff with jitter for Android
					baseBackoff := time.Duration(attempt) * 2 * time.Second
					jitter := time.Duration(time.Now().UnixNano()%1000) * time.Millisecond
					backoff := baseBackoff + jitter

					l.Info("Reconnection attempt", "attempt", attempt, "backoff", backoff, "recovery_cycle", recoveryAttempts+1)

					time.Sleep(backoff)

					if ctx.Err() != nil {
						return
					}

					// Acquire write lock for adapter replacement
					adapterMutex.Lock()

					// Close the old broken adapter
					l.Info("Closing broken MASQUE adapter")
					oldAdapter := adapter
					if oldAdapter != nil {
						oldAdapter.Close()
					}

					// Create a new MASQUE adapter from scratch
					l.Info("Creating new MASQUE adapter with fresh handshake")
					newAdapter, err := factory()
					if err != nil {
						l.Warn("Failed to create new MASQUE adapter", "attempt", attempt, "error", err)
						adapterMutex.Unlock()
						continue
					}

					// Replace the adapter safely first
					l.Debug("Replacing MASQUE adapter for packet forwarding")
					adapter = newAdapter
					connectionBroken.Store(false)

					// Reset timestamps
					now := time.Now().Unix()
					lastSuccessfulRead.Store(now)
					lastSuccessfulWrite.Store(now)

					adapterMutex.Unlock()

					// Now test connectivity after adapter is integrated
					l.Debug("Testing new MASQUE adapter with connectivity test")
					time.Sleep(2 * time.Second) // Allow packet forwarding to stabilize
					testCtx, testCancel := context.WithTimeout(ctx, ConnectivityTestTimeout)

					if err := usermodeTunTest(testCtx, l, tnet, testURL); err != nil {
						testCancel()
						l.Warn("New MASQUE adapter connectivity test failed", "attempt", attempt, "error", err, "connection_error", true)
						// Don't close the adapter since it's already integrated - let it try to recover naturally
						continue
					}
					testCancel()

					successfulRecovery = true
					lastRecoveryTime.Store(time.Now().Unix())
					l.Info("Connection recovery completed successfully", "attempt", attempt)
					break
				}

				// Handle recovery outcome
				if successfulRecovery {
					recoveryAttempts = 0 // Reset counter on success
					l.Info("MASQUE connection recovery successful")

					// Drain any queued connectionDown signals that occurred during recovery
					drained := 0
					for {
						select {
						case <-connectionDown:
							drained++
						default:
							// No more signals to drain
							goto drainComplete
						}
					}
				drainComplete:
					if drained > 0 {
						l.Info("Cleared stale recovery signals", "count", drained)
					}
					// Recovery successful, don't trigger reconnection
				} else {
					recoveryAttempts++
					l.Error("All reconnection attempts failed", "recovery_cycle", recoveryAttempts, "max_cycles", MaxRecoveryAttempts)

					// If we've exceeded max recovery attempts, wait longer before trying again
					if recoveryAttempts >= MaxRecoveryAttempts {
						l.Error("Maximum recovery attempts exceeded, waiting longer before retry")
						time.Sleep(60 * time.Second) // Wait 1 minute before trying again
						recoveryAttempts = 0         // Reset for next cycle
					} else {
						// Progressive delay between recovery cycles
						delayTime := time.Duration(recoveryAttempts*5) * time.Second
						l.Info("Waiting before next recovery cycle", "delay", delayTime)
						time.Sleep(delayTime)
					}

					// Only trigger reconnection if recovery failed and context not cancelled
					if ctx.Err() == nil {
						select {
						case connectionDown <- true:
						default:
						}
					}
				}
			}
		}
	}()
}
