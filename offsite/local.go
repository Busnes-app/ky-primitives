package offsite

import (
	"context"
	"io"
	"os"
	"path"
	"strings"
)

type localTarget struct{ dir string }

func (t *localTarget) Put(ctx context.Context, name string, r io.Reader, _ int64) error {
	name, err := cleanName(name)
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(t.dir, 0700); err != nil {
		return err
	}
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if parent := path.Dir(name); parent != "." {
		if err := root.MkdirAll(parent, 0700); err != nil {
			return err
		}
	}
	tmp, err := stagingName(name)
	if err != nil {
		return err
	}
	f, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(tmp)
	if _, err := io.Copy(f, &contextReader{ctx: ctx, r: r}); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return root.Rename(tmp, name)
}

func (t *localTarget) Get(ctx context.Context, name string) (io.ReadCloser, error) {
	name, err := cleanName(name)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return root.Open(name)
}

func (t *localTarget) Test(ctx context.Context) error {
	if err := t.Put(ctx, pingName, strings.NewReader("ping"), 4); err != nil {
		return err
	}
	root, err := os.OpenRoot(t.dir)
	if err != nil {
		return err
	}
	defer root.Close()
	return root.Remove(pingName)
}

type contextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}
