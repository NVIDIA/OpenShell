// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
)

// ProviderFromProto converts a proto Provider to an SDK Provider.
func ProviderFromProto(p *dm.Provider) *types.Provider {
	if p == nil {
		return nil
	}

	result := &types.Provider{
		Type: p.GetType(),
		Spec: types.ProviderSpec{
			Config:           CopyStringMap(p.GetConfig()),
			ProfileWorkspace: p.GetProfileWorkspace(),
		},
	}

	if m := p.GetMetadata(); m != nil {
		result.ID = m.GetId()
		result.Name = m.GetName()
		result.CreatedAt = TimeFromMillis(m.GetCreatedAtMs())
		result.Labels = CopyStringMap(m.GetLabels())
		result.Annotations = CopyStringMap(m.GetAnnotations())
		result.ResourceVersion = m.GetResourceVersion()
		result.Workspace = m.GetWorkspace()
		result.DeletionTimestamp = TimeFromMillisPtr(m.GetDeletionTimestampMs())
	}

	if expires := p.GetCredentialExpiresAtMs(); len(expires) > 0 {
		result.Spec.CredentialExpiresAt = make(map[string]time.Time, len(expires))
		for k, ms := range expires {
			result.Spec.CredentialExpiresAt[k] = TimeFromMillis(ms)
		}
	}

	if handles := p.GetCredentialHandles(); len(handles) > 0 {
		result.Spec.CredentialHandles = make(map[string]types.CredentialHandle, len(handles))
		for k, h := range handles {
			result.Spec.CredentialHandles[k] = types.CredentialHandle{
				Driver:   h.GetDriver(),
				Handle:   h.GetHandle(),
				Metadata: CopyStringMap(h.GetMetadata()),
			}
		}
	}

	return result
}

// ProviderToProto converts an SDK Provider to a proto Provider.
func ProviderToProto(p *types.Provider) *dm.Provider {
	if p == nil {
		return nil
	}

	result := &dm.Provider{
		Metadata: &dm.ObjectMeta{
			Id:                  p.ID,
			Name:                p.Name,
			CreatedAtMs:         MillisFromTime(p.CreatedAt),
			Labels:              CopyStringMap(p.Labels),
			Annotations:         CopyStringMap(p.Annotations),
			ResourceVersion:     p.ResourceVersion,
			Workspace:           p.Workspace,
			DeletionTimestampMs: MillisFromTimePtr(p.DeletionTimestamp),
		},
		Type:             p.Type,
		Credentials:      CopyStringMap(p.Spec.Credentials),
		Config:           CopyStringMap(p.Spec.Config),
		ProfileWorkspace: p.Spec.ProfileWorkspace,
	}

	if len(p.Spec.CredentialExpiresAt) > 0 {
		result.CredentialExpiresAtMs = make(map[string]int64, len(p.Spec.CredentialExpiresAt))
		for k, t := range p.Spec.CredentialExpiresAt {
			result.CredentialExpiresAtMs[k] = MillisFromTime(t)
		}
	}

	if len(p.Spec.CredentialHandles) > 0 {
		result.CredentialHandles = make(map[string]*dm.CredentialHandle, len(p.Spec.CredentialHandles))
		for k, h := range p.Spec.CredentialHandles {
			result.CredentialHandles[k] = &dm.CredentialHandle{
				Driver:   h.Driver,
				Handle:   h.Handle,
				Metadata: CopyStringMap(h.Metadata),
			}
		}
	}

	return result
}
