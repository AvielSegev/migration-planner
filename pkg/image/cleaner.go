package image

import (
	"os"
	"sync"
	"time"
)

type fileEntry struct {
	path     string
	deleteAt time.Time
}

type ImageCleaner struct {
	mu        sync.Mutex
	files     map[string]fileEntry
	interval  time.Duration
	stopCh    chan struct{}
	startOnce sync.Once
	stopOnce  sync.Once
}

func NewImageCleaner(interval time.Duration) *ImageCleaner {
	return &ImageCleaner{
		files:    make(map[string]fileEntry),
		interval: interval,
		stopCh:   make(chan struct{}),
	}
}

func (c *ImageCleaner) Register(path string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.files[path] = fileEntry{
		path:     path,
		deleteAt: time.Now().Add(ttl),
	}
}

func (c *ImageCleaner) Start() {
	c.startOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(c.interval)
			defer ticker.Stop()
			for {
				select {
				case <-ticker.C:
					c.cleanup()
				case <-c.stopCh:
					return
				}
			}
		}()
	})
}

func (c *ImageCleaner) Stop() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
}

func (c *ImageCleaner) cleanup() {
	now := time.Now()

	var expired []string

	c.mu.Lock()
	for path, entry := range c.files {
		if now.After(entry.deleteAt) {
			expired = append(expired, path)
			delete(c.files, path)
		}
	}
	c.mu.Unlock()

	for _, p := range expired {
		_ = os.Remove(p)
	}
}
