package probe

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/altshiftab/altshift_web_security/pkg/tls/observation"
)

// recordingConn keeps a copy of everything the server sent, which is what makes the
// 0-RTT check possible: the standard library hands back a connection, not the bytes
// that built it, and the session ticket the answer is in never surfaces through its
// API.
type recordingConn struct {
	net.Conn

	mutex    sync.Mutex
	received bytes.Buffer
}

func (conn *recordingConn) Read(buffer []byte) (int, error) {
	read, err := conn.Conn.Read(buffer)

	if read > 0 {
		conn.mutex.Lock()
		conn.received.Write(buffer[:read])
		conn.mutex.Unlock()
	}

	return read, err
}

func (conn *recordingConn) stream() []byte {
	conn.mutex.Lock()
	defer conn.mutex.Unlock()

	return bytes.Clone(conn.received.Bytes())
}

// probeSession completes one ordinary handshake, which is the only way to see two
// things: a stapled OCSP response, which the standard library surfaces, and a
// session ticket, which it does not.
//
// The certificate is not verified. Whether it chains to a trusted root is a
// different question from what this reports on, and refusing to look at a server's
// TLS because its certificate has expired would be a poor trade.
func (prober *prober) probeSession(ctx context.Context) *observation.Session {
	session := &observation.Session{}

	if !prober.takeConnection() {
		session.Error = "the connection budget was exhausted"
		prober.noteIncomplete("session", session.Error)

		return session
	}

	dialer := &net.Dialer{Timeout: prober.settings.ConnectTimeout}

	raw, err := dialer.DialContext(ctx, "tcp", prober.address)
	if err != nil {
		session.Error = fmt.Sprintf("dial: %v", err)

		return session
	}
	defer func() { _ = raw.Close() }()

	recorder := &recordingConn{Conn: raw}

	keyLog := &strings.Builder{}
	keyLogMutex := &sync.Mutex{}

	conn := tls.Client(recorder, &tls.Config{
		ServerName: prober.serverName,
		//nolint:gosec // What the certificate says is a separate question; refusing
		// to look at a server's TLS because its certificate does not verify would
		// withhold every finding this makes for the sake of one it does not.
		InsecureSkipVerify: true,
		KeyLogWriter:       &lockedWriter{writer: keyLog, mutex: keyLogMutex},
		ClientSessionCache: tls.NewLRUClientSessionCache(4),
	})

	deadline := time.Now().Add(prober.settings.HandshakeTimeout)
	if err := conn.SetDeadline(deadline); err != nil {
		session.Error = fmt.Sprintf("set deadline: %v", err)

		return session
	}

	if err := conn.HandshakeContext(ctx); err != nil {
		session.Error = fmt.Sprintf("handshake: %v", err)

		return session
	}

	state := conn.ConnectionState()

	session.Established = true
	session.Version = state.Version
	session.CipherSuite = state.CipherSuite
	session.OcspStapled = len(state.OCSPResponse) != 0

	session.EarlyData = prober.readEarlyData(conn, recorder, keyLog, keyLogMutex, state)

	return session
}

// readEarlyData draws the session ticket out of the server and reads whether it
// offers 0-RTT.
//
// A ticket arrives after the handshake, so the connection has to be used before
// there is anything to read. A request is sent and the answer read until the server
// stops talking or the deadline passes; whatever arrived is then decrypted.
func (prober *prober) readEarlyData(
	conn *tls.Conn,
	recorder *recordingConn,
	keyLog *strings.Builder,
	keyLogMutex *sync.Mutex,
	state tls.ConnectionState,
) *observation.EarlyData {
	if state.Version < tls.VersionTLS13 {
		// 0-RTT arrived with TLS 1.3. There is nothing to determine below it, and
		// nothing to report.
		return &observation.EarlyData{
			Determined: true,
			Reason:     "the connection negotiated a version older than TLS 1.3, which has no early data",
		}
	}

	// A ticket is sent when the server feels like it, usually right after the
	// handshake and sometimes only after the first request.
	if err := conn.SetDeadline(time.Now().Add(prober.settings.HandshakeTimeout)); err == nil {
		request := fmt.Sprintf(
			"HEAD / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
			prober.serverName,
		)

		if _, err := conn.Write([]byte(request)); err == nil {
			buffer := make([]byte, 4096)
			for {
				if _, err := conn.Read(buffer); err != nil {
					break
				}
			}
		}
	}

	keyLogMutex.Lock()
	secrets := parseKeyLog(keyLog.String())
	keyLogMutex.Unlock()

	return inspectEarlyData(recorder.stream(), secrets, state.CipherSuite)
}

// lockedWriter serialises writes to the key log, which crypto/tls writes from the
// handshake goroutine while this reads it from another.
type lockedWriter struct {
	writer *strings.Builder
	mutex  *sync.Mutex
}

func (writer *lockedWriter) Write(data []byte) (int, error) {
	writer.mutex.Lock()
	defer writer.mutex.Unlock()

	written, err := writer.writer.Write(data)
	if err != nil {
		return written, fmt.Errorf("string builder write: %w", err)
	}

	return written, nil
}
