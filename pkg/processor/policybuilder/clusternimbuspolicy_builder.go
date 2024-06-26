// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package policybuilder

import (
	"context"

	"github.com/go-logr/logr"
	"github.com/pkg/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	v1alpha1 "github.com/5GSEC/nimbus/api/v1alpha1"
	processorerrors "github.com/5GSEC/nimbus/pkg/processor/errors"
	"github.com/5GSEC/nimbus/pkg/processor/intentbinder"
)

// BuildClusterNimbusPolicy generates a ClusterNimbusPolicy based on given
// SecurityIntents and ClusterSecurityIntentBinding.
func BuildClusterNimbusPolicy(ctx context.Context, logger logr.Logger, k8sClient client.Client, scheme *runtime.Scheme, csib v1alpha1.ClusterSecurityIntentBinding) (*v1alpha1.ClusterNimbusPolicy, error) {
	logger.Info("Building ClusterNimbusPolicy")
	intents := intentbinder.ExtractIntents(ctx, k8sClient, &csib)
	if len(intents) == 0 {
		logger.Info("ClusterNimbusPolicy creation aborted since no SecurityIntents found")
		return nil, processorerrors.ErrSecurityIntentsNotFound
	}

	var nimbusRules []v1alpha1.NimbusRules
	for _, intent := range intents {
		nimbusRules = append(nimbusRules, v1alpha1.NimbusRules{
			ID:          intent.Spec.Intent.ID,
			Description: intent.Spec.Intent.Description,
			Rule: v1alpha1.Rule{
				RuleAction: intent.Spec.Intent.Action,
				Params:     intent.Spec.Intent.Params,
			},
		})
	}

	clusterNp := &v1alpha1.ClusterNimbusPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:   csib.Name,
			Labels: csib.Labels,
		},
		Spec: v1alpha1.ClusterNimbusPolicySpec{
			NodeSelector:     csib.Spec.Selector.NodeSelector,
			NsSelector:       csib.Spec.Selector.NsSelector,
			WorkloadSelector: csib.Spec.Selector.WorkloadSelector,
			NimbusRules:      nimbusRules,
		},
	}

	if err := ctrl.SetControllerReference(&csib, clusterNp, scheme); err != nil {
		return nil, errors.Wrap(err, "failed to set NimbusPolicy OwnerReference")
	}

	logger.Info("ClusterNimbusPolicy built successfully", "ClusterNimbusPolicy.Name", clusterNp.Name)
	return clusterNp, nil
}
