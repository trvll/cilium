// SPDX-License-Identifier: Apache-2.0
// Copyright 2018 Authors of Cilium

//go:build !privileged_tests
// +build !privileged_tests

package dnsproxy

import (
	. "gopkg.in/check.v1"
)

type DNSProxyHelperTestSuite struct{}

var _ = Suite(&DNSProxyHelperTestSuite{})
