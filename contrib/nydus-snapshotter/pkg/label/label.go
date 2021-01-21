/*
 * Copyright (c) 2020. Ant Group. All rights reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package label

const (
	Signature = "containerd.io/snapshot/nydus-signature"

	ImageRef          = "containerd.io/snapshot/cri.image-ref"
	ImagePullSecret   = "containerd.io/snapshot/pullsecret"
	ImagePullUsername = "containerd.io/snapshot/pullusername"

	TargetSnapshotLabel = "containerd.io/snapshot.ref"
	CRIImageLayer       = "containerd.io/snapshot/cri.image-layers"
	CRIDigest           = "containerd.io/snapshot/cri.layer-digest"
	RemoteLabel         = "containerd.io/snapshot/remote"
	NydusMetaLayer      = "containerd.io/snapshot/nydus-bootstrap"
	NydusDataLayer      = "containerd.io/snapshot/nydus-blob"
)
