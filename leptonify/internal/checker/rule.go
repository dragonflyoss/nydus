/*
 * Copyright (c) 2026. Lepton Developers. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package checker

import "context"

// Rule is a single consistency check executed by the Checker. Rules are run
// sequentially; the first failing rule aborts the check.
type Rule interface {
	// Name is a short identifier used in logs and error messages.
	Name() string
	// Validate runs the rule. A nil error means the rule passed (or was
	// skipped because its inputs were not applicable).
	Validate(ctx context.Context) error
}
