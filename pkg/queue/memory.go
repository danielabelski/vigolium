package queue

import (
	"context"
	"io"
	"sync"
	"sync/atomic"
)

// MemoryQueue is a pure in-memory FIFO queue with no disk or network backend.
//
// It exists so a server that does not need durable task spillover (the common
// case: any server not running scan-on-receive) can still satisfy the Queue
// interface for diagnostics/metrics without opening a LevelDB directory, spawning
// drainer/cleanup goroutines, or taking the on-disk exclusive lock that would
// otherwise block a second server instance on the same host.
type MemoryQueue struct {
	ch        chan *ScanTask
	closed    chan struct{}
	closeOnce sync.Once

	enqueued  atomic.Int64
	dequeued  atomic.Int64
	completed atomic.Int64
}

// memoryQueueDefaultBuffer bounds the in-memory backlog so a runaway producer
// can't grow it without limit; Enqueue blocks (with context) once it is full.
const memoryQueueDefaultBuffer = 10000

// NewMemoryQueue creates an empty in-memory queue. buffer <= 0 uses the default.
func NewMemoryQueue(buffer int) *MemoryQueue {
	if buffer <= 0 {
		buffer = memoryQueueDefaultBuffer
	}
	return &MemoryQueue{
		ch:     make(chan *ScanTask, buffer),
		closed: make(chan struct{}),
	}
}

// Enqueue adds a task, blocking while the buffer is full until space frees up,
// the context is cancelled, or the queue is closed.
func (q *MemoryQueue) Enqueue(ctx context.Context, task *ScanTask) error {
	select {
	case <-q.closed:
		return ErrQueueClosed
	default:
	}
	select {
	case q.ch <- task:
		q.enqueued.Add(1)
		return nil
	case <-q.closed:
		return ErrQueueClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Dequeue returns the next task, blocking until one is available, the context is
// cancelled, or the queue is closed and drained (io.EOF).
func (q *MemoryQueue) Dequeue(ctx context.Context) (*ScanTask, error) {
	select {
	case task := <-q.ch:
		q.dequeued.Add(1)
		return task, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-q.closed:
		// Drain any items buffered before close before signalling EOF.
		select {
		case task := <-q.ch:
			q.dequeued.Add(1)
			return task, nil
		default:
			return nil, io.EOF
		}
	}
}

// Ack marks a task completed. In-memory delivery is at-most-once, so this only
// updates metrics.
func (q *MemoryQueue) Ack(_ string) error {
	q.completed.Add(1)
	return nil
}

// Close prevents new Enqueue calls; Dequeue drains remaining items then returns
// io.EOF. Safe to call multiple times.
func (q *MemoryQueue) Close() error {
	q.closeOnce.Do(func() { close(q.closed) })
	return nil
}

// Metrics reports the in-memory queue counters. Disk fields stay zero.
func (q *MemoryQueue) Metrics() *QueueMetrics {
	return &QueueMetrics{
		Depth:          int64(len(q.ch)),
		TotalEnqueued:  q.enqueued.Load(),
		TotalDequeued:  q.dequeued.Load(),
		TotalCompleted: q.completed.Load(),
	}
}
