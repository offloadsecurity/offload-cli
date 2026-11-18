package scanners

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// maxLineBytes bounds a single source line read for verdict context. A longer
// line (minified code, a blob) is skipped rather than buffered.
const maxLineBytes = 64 << 10

// sourceLines reads, for each file gitleaks reported, only the lines it
// reported on (gitleaks' JSON report omits the line itself). Each file is read
// once, streaming, and only up to its last wanted line. A file outside the
// scanned directory, a non-regular file, an unreadable file, an over-long
// line or a binary line yields no entry; the classifier then judges the
// match alone.
func sourceLines(dir string, entries []gitleaksV8) map[string]map[int]string {
	wanted := map[string]map[int]bool{}
	for _, e := range entries {
		if e.File == "" || e.StartLine < 1 {
			continue
		}
		if wanted[e.File] == nil {
			wanted[e.File] = map[int]bool{}
		}
		wanted[e.File][e.StartLine] = true
	}
	out := make(map[string]map[int]string, len(wanted))
	root, err := filepath.Abs(dir)
	if err != nil {
		return out
	}
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	for file, want := range wanted {
		p, ok := confined(root, file)
		if !ok {
			continue
		}
		out[file] = readLines(p, want)
	}
	return out
}

// confined resolves file (absolute, or relative to the working directory as
// gitleaks reports it) and confirms it is a regular file inside root.
func confined(root, file string) (string, bool) {
	p, err := filepath.Abs(file)
	if err != nil {
		return "", false
	}
	if p, err = filepath.EvalSymlinks(p); err != nil {
		return "", false
	}
	if p != root && !strings.HasPrefix(p, root+string(filepath.Separator)) {
		return "", false
	}
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return "", false
	}
	return p, true
}

func readLines(path string, want map[int]bool) map[int]string {
	got := map[int]string{}
	last := 0
	for n := range want {
		if n > last {
			last = n
		}
	}
	f, err := os.Open(path)
	if err != nil {
		return got
	}
	defer f.Close()
	br := bufio.NewReaderSize(f, maxLineBytes)
	for n := 1; n <= last; n++ {
		line, tooLong, err := readLine(br)
		if want[n] && !tooLong && utf8.Valid(line) && bytes.IndexByte(line, 0) < 0 {
			got[n] = string(line)
		}
		if err != nil {
			break
		}
	}
	return got
}

// readLine returns the next line without its terminator. A line longer than
// the reader's buffer is consumed and reported as tooLong.
func readLine(br *bufio.Reader) (line []byte, tooLong bool, err error) {
	for {
		chunk, e := br.ReadSlice('\n')
		if errors.Is(e, bufio.ErrBufferFull) {
			tooLong = true
			continue
		}
		if !tooLong {
			line = bytes.TrimRight(chunk, "\r\n")
		}
		if e == io.EOF && len(chunk) == 0 && !tooLong {
			return nil, false, e
		}
		return line, tooLong, e
	}
}
