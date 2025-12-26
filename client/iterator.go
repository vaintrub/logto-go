package client

import (
	"context"
)

// PageResult contains a page of items along with pagination metadata.
type PageResult[T any] struct {
	Items []T // Items for this page
	Total int // Total number of items (-1 if unknown)
}

// PageFetcher is a function type that fetches a page of items.
// It receives page number (1-based, as Logto API uses) and page size,
// returns PageResult with items and total count.
type PageFetcher[T any] func(ctx context.Context, page, pageSize int) (PageResult[T], error)

// IteratorConfig holds configuration for pagination.
type IteratorConfig struct {
	// PageSize is the number of items per page.
	// Default: 20 (Logto API default).
	PageSize int
}

// DefaultIteratorConfig returns sensible defaults matching Logto API.
func DefaultIteratorConfig() IteratorConfig {
	return IteratorConfig{
		PageSize: 20,
	}
}

// Iterator provides generic pagination for any slice type.
// Use Next(ctx) to iterate through results.
//
// Example usage:
//
//	iter := client.ListUsers(client.IteratorConfig{PageSize: 50})
//	for iter.Next(ctx) {
//	    user := iter.Item()
//	    fmt.Println(user.ID)
//	}
//	if err := iter.Err(); err != nil {
//	    return err
//	}
//
// For cursor-based pagination adapter:
//
//	iter := client.ListUsers(client.IteratorConfig{PageSize: 100})
//	items, _ := iter.Collect(ctx)
//	hasMore := iter.HasMore()
//	total := iter.Total()
type Iterator[T any] struct {
	fetcher PageFetcher[T]
	config  IteratorConfig
	page    int   // current page (0 means not started, will be 1 on first fetch)
	items   []T   // current page items
	index   int   // current index in items (-1 means before first item)
	err     error // last error
	done    bool  // iteration complete
	total   int   // total items from API (-1 if unknown)
}

// NewIterator creates a new generic iterator with the given fetcher and config.
func NewIterator[T any](fetcher PageFetcher[T], config IteratorConfig) *Iterator[T] {
	if config.PageSize <= 0 {
		config.PageSize = 20
	}
	return &Iterator[T]{
		fetcher: fetcher,
		config:  config,
		page:    0,
		index:   -1,
		total:   -1,
	}
}

// Next advances the iterator to the next item.
// Returns true if there is an item available via Item().
// The context is used for API calls to fetch the next page.
func (it *Iterator[T]) Next(ctx context.Context) bool {
	if it.err != nil || it.done {
		return false
	}

	// Move to next item in current page
	if it.index < len(it.items)-1 {
		it.index++
		return true
	}

	// Fetch next page
	it.page++
	result, err := it.fetcher(ctx, it.page, it.config.PageSize)
	if err != nil {
		it.err = err
		return false
	}

	// Update total if provided
	if result.Total >= 0 {
		it.total = result.Total
	}

	if len(result.Items) == 0 {
		it.done = true
		return false
	}

	it.items = result.Items
	it.index = 0
	return true
}

// Item returns a pointer to the current item.
// Returns nil if the iterator is not positioned on a valid item.
func (it *Iterator[T]) Item() *T {
	if it.index < 0 || it.index >= len(it.items) {
		return nil
	}
	return &it.items[it.index]
}

// Err returns any error that occurred during iteration.
func (it *Iterator[T]) Err() error {
	return it.err
}

// Collect fetches all remaining items and returns them as a slice.
// Pre-allocates memory based on page size for better performance.
func (it *Iterator[T]) Collect(ctx context.Context) ([]T, error) {
	// Pre-allocate for 2 pages as a reasonable starting point
	all := make([]T, 0, it.config.PageSize*2)
	for it.Next(ctx) {
		all = append(all, *it.Item())
	}
	return all, it.Err()
}

// Reset resets the iterator to its initial state.
// After calling Reset, you can iterate through items again.
func (it *Iterator[T]) Reset() {
	it.page = 0
	it.items = nil
	it.index = -1
	it.err = nil
	it.done = false
	it.total = -1
}

// Total returns the total number of items available.
// Returns -1 if the total is unknown (no API call made yet or API doesn't provide it).
// This value is updated after each page fetch from the Total-Number header.
func (it *Iterator[T]) Total() int {
	return it.total
}

// HasMore returns true if there are more items to iterate.
// This is useful for cursor-based pagination adapters.
// Returns false if iteration is complete or an error occurred.
//
// Note: This may return true even when there are no more items if the last page
// was exactly PageSize items. The next call to Next() will return false in that case.
func (it *Iterator[T]) HasMore() bool {
	if it.err != nil || it.done {
		return false
	}

	// If we know the total, we can be precise
	if it.total >= 0 {
		fetched := (it.page-1)*it.config.PageSize + it.index + 1
		return fetched < it.total
	}

	// If we haven't fetched yet, there might be more
	if it.page == 0 {
		return true
	}

	// If last page was full, there might be more
	return len(it.items) == it.config.PageSize
}
