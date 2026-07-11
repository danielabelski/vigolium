package queue

import (
	"context"
	"errors"
	"io"
	"testing"
	"time"
)

func TestMemoryQueue_EnqueueDequeueOrder(t *testing.T) {
	q := NewMemoryQueue(4)
	ctx := context.Background()

	for _, id := range []string{"a", "b", "c"} {
		if err := q.Enqueue(ctx, &ScanTask{ID: id, URL: "http://x/" + id}); err != nil {
			t.Fatalf("Enqueue %s: %v", id, err)
		}
	}
	for _, want := range []string{"a", "b", "c"} {
		task, err := q.Dequeue(ctx)
		if err != nil {
			t.Fatalf("Dequeue: %v", err)
		}
		if task.ID != want {
			t.Fatalf("FIFO order: got %s, want %s", task.ID, want)
		}
	}
	if m := q.Metrics(); m.TotalEnqueued != 3 || m.TotalDequeued != 3 {
		t.Fatalf("metrics = %+v, want 3 enqueued / 3 dequeued", m)
	}
}

func TestMemoryQueue_CloseDrainsThenEOF(t *testing.T) {
	q := NewMemoryQueue(4)
	ctx := context.Background()
	_ = q.Enqueue(ctx, &ScanTask{ID: "last", URL: "http://x/last"})

	if err := q.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// Item buffered before Close is still delivered.
	task, err := q.Dequeue(ctx)
	if err != nil || task == nil || task.ID != "last" {
		t.Fatalf("Dequeue after close = (%v, %v), want the buffered task", task, err)
	}
	// Then EOF.
	if _, err := q.Dequeue(ctx); !errors.Is(err, io.EOF) {
		t.Fatalf("drained Dequeue err = %v, want io.EOF", err)
	}
	// Enqueue after close is rejected.
	if err := q.Enqueue(ctx, &ScanTask{ID: "x", URL: "http://x"}); !errors.Is(err, ErrQueueClosed) {
		t.Fatalf("Enqueue after close err = %v, want ErrQueueClosed", err)
	}
}

func TestMemoryQueue_DequeueRespectsContext(t *testing.T) {
	q := NewMemoryQueue(4)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()

	_, err := q.Dequeue(ctx) // nothing queued; should unblock on ctx timeout
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Dequeue err = %v, want context.DeadlineExceeded", err)
	}
}
