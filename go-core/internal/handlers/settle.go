package handlers

import "net/http"

// countingWriter tallies delivered body bytes so a quota reservation
// (taken for the full projected size) can be settled down to actual
// bytes when the stream closes, aborts mid-transfer, or answers with a
// range/conditional status. Header management is promoted from the
// wrapped ResponseWriter unchanged.
type countingWriter struct {
	http.ResponseWriter
	written int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.ResponseWriter.Write(p)
	c.written += int64(n)
	return n, err
}
