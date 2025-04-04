package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"

	"hauler.dev/go/hauler/pkg/consts"
)

var (
	ContentGroupVersion    = schema.GroupVersion{Group: consts.ContentGroup, Version: "v1alpha1"}
	CollectionGroupVersion = schema.GroupVersion{Group: consts.CollectionGroup, Version: "v1alpha1"}
)
