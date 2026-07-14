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
			Config: CopyStringMap(p.GetConfig()),
		},
	}

	if m := p.GetMetadata(); m != nil {
		result.ID = m.GetId()
		result.Name = m.GetName()
		result.CreatedAt = TimeFromMillis(m.GetCreatedAtMs())
		result.Labels = CopyStringMap(m.GetLabels())
		result.ResourceVersion = m.GetResourceVersion()
	}

	if expires := p.GetCredentialExpiresAtMs(); len(expires) > 0 {
		result.Spec.CredentialExpiresAt = make(map[string]time.Time, len(expires))
		for k, ms := range expires {
			result.Spec.CredentialExpiresAt[k] = TimeFromMillis(ms)
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
			Id:              p.ID,
			Name:            p.Name,
			CreatedAtMs:     MillisFromTime(p.CreatedAt),
			Labels:          CopyStringMap(p.Labels),
			ResourceVersion: p.ResourceVersion,
		},
		Type:        p.Type,
		Credentials: CopyStringMap(p.Spec.Credentials),
		Config:      CopyStringMap(p.Spec.Config),
	}

	if len(p.Spec.CredentialExpiresAt) > 0 {
		result.CredentialExpiresAtMs = make(map[string]int64, len(p.Spec.CredentialExpiresAt))
		for k, t := range p.Spec.CredentialExpiresAt {
			result.CredentialExpiresAtMs[k] = MillisFromTime(t)
		}
	}

	return result
}
