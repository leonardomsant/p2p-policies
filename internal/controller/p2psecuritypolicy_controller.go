/*
Copyright 2025.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	api "github.com/leonardomsant/p2p-policies/api/v1"
	"github.com/leonardomsant/p2p-policies/pkg/swanctl"
)

// P2PSecurityPolicyReconciler reconciles a P2PSecurityPolicy object
type P2PSecurityPolicyReconciler struct {
	client.Client
	Scheme *runtime.Scheme
}

//+kubebuilder:rbac:groups=p2ppolicies.starlingx.windriver.com,resources=p2psecuritypolicies,verbs=get;list;watch;create;update;patch;delete
//+kubebuilder:rbac:groups=p2ppolicies.starlingx.windriver.com,resources=p2psecuritypolicies/status,verbs=get;update;patch
//+kubebuilder:rbac:groups=p2ppolicies.starlingx.windriver.com,resources=p2psecuritypolicies/finalizers,verbs=update

// Reconcile is part of the main kubernetes reconciliation loop which aims to
// move the current state of the cluster closer to the desired state.
// TODO(user): Modify the Reconcile function to compare the state specified by
// the P2PSecurityPolicy object against the actual cluster state, and then
// perform operations to make the cluster state reflect the state specified by
// the user.
//
// For more details, check Reconcile and its Result here:
// - https://pkg.go.dev/sigs.k8s.io/controller-runtime@v0.17.3/pkg/reconcile
func (r *P2PSecurityPolicyReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.Info("Reconciling P2PSecurityPolicy custom resource")

	var p2pConf api.P2PSecurityPolicy
	if err := r.Get(ctx, req.NamespacedName, &p2pConf); err != nil {
		log.Error(err, "Unable to fetch P2PSecurityPolicy")
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	configFile := new(swanctl.ConfigurationFile)
	if err := configFile.Generate(p2pConf); err != nil {
		log.Error(err, "Unable generate configuration file")
	}

	if err := configFile.LoadConnections(); err != nil {
		log.Error(err, "Unable to load connections")
	}

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *P2PSecurityPolicyReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&api.P2PSecurityPolicy{}).
		Complete(r)
}
