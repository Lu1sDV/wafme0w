package browserruntime

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

const maxMessageBytes = 8 << 20

// Pipe speaks Chromium's NUL-delimited private CDP protocol, not WebSocket framing.
// Its method set satisfies Rod's cdp.WebSocketable without a listening CDP port.
type Pipe struct {
	reader  *bufio.Reader
	writer  io.Writer
	writeMu sync.Mutex
}

func newPipe(reader io.Reader, writer io.Writer) *Pipe {
	return &Pipe{reader: bufio.NewReaderSize(reader, 64<<10), writer: writer}
}

func (p *Pipe) Read() ([]byte, error) {
	var message []byte
	for {
		part, err := p.reader.ReadSlice(0)
		if err == nil {
			part = part[:len(part)-1]
		}
		if len(part) > maxMessageBytes-len(message) {
			return nil, errors.New("browser CDP message exceeds limit")
		}
		message = append(message, part...)
		if err == nil {
			if !json.Valid(message) {
				return nil, errors.New("browser CDP message is not valid JSON")
			}
			return message, nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			return nil, err
		}
	}
}

func (p *Pipe) Send(message []byte) error {
	if len(message) > maxMessageBytes || bytes.IndexByte(message, 0) >= 0 || !json.Valid(message) {
		return errors.New("invalid or oversized browser CDP command")
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if n, err := p.writer.Write(message); err != nil {
		return err
	} else if n != len(message) {
		return io.ErrShortWrite
	}
	if n, err := p.writer.Write([]byte{0}); err != nil {
		return err
	} else if n != 1 {
		return io.ErrShortWrite
	}
	return nil
}
