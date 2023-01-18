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

type DescartesIterator struct {
	cursores  []int
	valLists  [][]interface{}
	cursorMap map[string]int
	skip      func(item *DescartesItem) bool
}

func (c *DescartesIterator) Next() *DescartesItem {
	var carry bool
	for idx := range c.cursores {
		if c.cursores[idx]+1 < len(c.valLists[idx]) {
			carry = false
			c.cursores[idx]++
			break
		} else {
			c.cursores[idx] = 0
			carry = true
		}
	}

	if carry {
		for idx := range c.cursores {
			c.cursores[idx] = len(c.valLists[idx]) - 1
		}
		return nil
	}

	item := &DescartesItem{vals: make(map[string]interface{})}
	for name, idx := range c.cursorMap {
		item.vals[name] = c.valLists[idx][c.cursores[idx]]
	}

	if c.skip != nil && c.skip(item) {
		return nil
	}
	return item
}

func (c *DescartesIterator) HasNext() bool {
	for idx := range c.cursores {
		if c.cursores[idx]+1 < len(c.valLists[idx]) {
			return true
		}
	}
	return false
}

func (c *DescartesIterator) Register(name string, vals []interface{}) *DescartesIterator {
	if c.cursorMap == nil {
		c.cursorMap = make(map[string]int)
	}

	c.cursores = append(c.cursores, 0)
	c.valLists = append(c.valLists, vals)
	c.cursorMap[name] = len(c.cursores) - 1

	c.cursores[0] = -1

	return c
}

func (c *DescartesIterator) Skip(f func(item *DescartesItem) bool) *DescartesIterator {
	c.skip = f
	return c
}
