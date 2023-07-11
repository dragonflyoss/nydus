package tool

import (
	"fmt"
	"sort"
	"strings"
)

type DescartesItem struct {
	vals map[string]interface{}
}

func (d *DescartesItem) GetString(name string) string {
	return d.vals[name].(string)
}

func (d *DescartesItem) GetBool(name string) bool {
	return d.vals[name].(bool)
}

func (d *DescartesItem) Str() string {

	names := make([]string, 0, len(d.vals))
	for name := range d.vals {
		names = append(names, name)
	}
	sort.SliceStable(names, func(i, j int) bool { return names[i] < names[j] })

	var sb strings.Builder
	first := true
	for _, name := range names {
		if first {
			first = false
		} else {
			sb.WriteString(",")
		}
		sb.WriteString(name)
		sb.WriteString("=")

		val := d.vals[name]
		if s, ok := val.(string); ok {
			sb.WriteString(s)
		} else {
			sb.WriteString(fmt.Sprintf("%v", val))
		}
	}
	return sb.String()
}

func (d *DescartesItem) GetUInt64(name string) uint64 {
	return d.vals[name].(uint64)
}

// Generator of Cartesian product.
//
// An example is below:
//
//		import (
//	       "fmt"
//	       "github.com/dragonflyoss/image-service/smoke/tests/tool"
//	   )
//
//		products := tool.DescartesIterator{}
//		products.
//			Dimension("name", []interface{}{"foo", "imoer", "morgan"}).
//			Dimension("age", []interface{}{"20", "30"}).
//			Skip(func(item *tool.DescartesItem) bool {
//	   		// skip ("morgan", "30")
//	   		return item.GetString("name") == "morgan" && param.GetString("age") == "30"
//			})
//
//	   // output:
//	   //       age: 20, name: foo
//	   //       age: 20, name: imoer
//	   //       age: 20, name: morgan
//	   //       age: 30, name: foo
//	   //       age: 30, name: imoer
//	   for products.HasNext(){
//	       item := products.Next()
//	       fmt.Println(item.Str())
//	   }
type DescartesIterator struct {
	cursores  []int
	valLists  [][]interface{}
	cursorMap map[string]int
	skip      func(item *DescartesItem) bool

	// cached result
	nextCursors []int
	nextItem    *DescartesItem
	hasNext     *bool
}

// The existence of result is consistent with result of `HasNext()`.
//
// It is recommended to call `HasNext()` before `Next()`. However, `Next()` can be used without
// `HasNext()` called. If there is no left item, nil is returned.
func (c *DescartesIterator) Next() *DescartesItem {
	if c.hasNext == nil {
		c.calNext()
	}
	if !*c.hasNext {
		return nil
	}

	c.cursores = c.nextCursors
	result := c.nextItem

	c.clearNext()

	return result
}

func (c *DescartesIterator) HasNext() bool {
	c.calNext()
	return *c.hasNext
}

func (c *DescartesIterator) calNext() {

	cursors := make([]int, len(c.cursores))
	copy(cursors, c.cursores)

	item := &DescartesItem{vals: make(map[string]interface{})}
	for {
		carried := false
		for idx := range cursors {
			if cursors[idx]+1 < len(c.valLists[idx]) {
				carried = true
				cursors[idx]++
				break
			} else {
				carried = false
				cursors[idx] = 0
			}
		}
		if !carried {
			c.noNext()
			return
		}

		for name, idx := range c.cursorMap {
			item.vals[name] = c.valLists[idx][cursors[idx]]
		}
		if c.skip == nil || !c.skip(item) {
			c.haveNext(cursors, item)
			return
		}
	}
}

func (c *DescartesIterator) noNext() {
	c.hasNext = func(val bool) *bool { return &val }(false)
	c.nextCursors = nil
	c.nextItem = nil
}

func (c *DescartesIterator) haveNext(nextCursors []int, nextItem *DescartesItem) {
	c.hasNext = func(val bool) *bool { return &val }(true)
	c.nextCursors = nextCursors
	c.nextItem = nextItem
}

func (c *DescartesIterator) clearNext() {
	c.hasNext = nil
	c.nextCursors = nil
	c.nextItem = nil
}

func (c *DescartesIterator) Dimension(name string, vals []interface{}) *DescartesIterator {
	if c.cursorMap == nil {
		c.cursorMap = make(map[string]int)
	}

	c.cursores = append(c.cursores, 0)
	c.valLists = append(c.valLists, vals)
	c.cursorMap[name] = len(c.cursores) - 1

	c.cursores[0] = -1

	return c
}

// It's used to skip certain item.
//
// Note: The closure is strongly recommended to be idempotent. Because it's used every time `HasNext()` called.
func (c *DescartesIterator) Skip(f func(item *DescartesItem) bool) *DescartesIterator {
	c.skip = f
	return c
}
