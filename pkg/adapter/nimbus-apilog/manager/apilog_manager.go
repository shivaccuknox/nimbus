// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of Nimbus

package manager

import (
	"context"

	netv1 "k8s.io/api/networking/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/5GSEC/nimbus/api/v1alpha1"
	"github.com/5GSEC/nimbus/pkg/adapter/idpool"
	"github.com/5GSEC/nimbus/pkg/adapter/k8s"
	"github.com/5GSEC/nimbus/pkg/adapter/nimbus-apilog/bpf"
	globalwatcher "github.com/5GSEC/nimbus/pkg/adapter/watcher"
)

var (
	scheme    = runtime.NewScheme()
	k8sClient client.Client
)

func init() {
	utilruntime.Must(v1alpha1.AddToScheme(scheme))
	utilruntime.Must(netv1.AddToScheme(scheme))
	k8sClient = k8s.NewOrDie(scheme)
}

func Run(ctx context.Context) {

	// Watch ClusterNimbusPolicies only
	cwnpCh := make(chan string)
	deletedCwnpCh := make(chan *unstructured.Unstructured)
	go globalwatcher.WatchClusterNimbusPolicies(ctx, cwnpCh, deletedCwnpCh)

	for {
		select {
		case <-ctx.Done():
			close(cwnpCh)
			close(deletedCwnpCh)
			return
		case <-cwnpCh:
			reconcileLogging(ctx)
		case <-deletedCwnpCh:
			reconcileLogging(ctx)
		}
	}
}

func reconcileLogging(ctx context.Context) {
	logger := log.FromContext(ctx)

	// Go through all the cwnp, and check if atleast one of them is an enable
	var cwnps v1alpha1.ClusterNimbusPolicyList
	if err := k8sClient.List(ctx, &cwnps); err != nil {
		logger.Error(err, "failed to list cluster nimbus policies")
		return
	}

	var enableLogging = false
	for _, cwnp := range cwnps.Items {
		for _, rule := range cwnp.Spec.NimbusRules {
			if idpool.IsIdSupportedBy(rule.ID, "apiLogger") {
				enableLogging = true
			}
		}
	}

	// Apply to engine
	if enableLogging {
		bpf.Bh.Run()
	} else {
		bpf.Bh.Stop()
	}
}
