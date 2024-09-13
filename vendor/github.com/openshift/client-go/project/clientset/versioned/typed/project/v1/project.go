// Code generated by client-gen. DO NOT EDIT.

package v1

import (
	"context"

	v1 "github.com/openshift/api/project/v1"
	projectv1 "github.com/openshift/client-go/project/applyconfigurations/project/v1"
	scheme "github.com/openshift/client-go/project/clientset/versioned/scheme"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	gentype "k8s.io/client-go/gentype"
)

// ProjectsGetter has a method to return a ProjectInterface.
// A group's client should implement this interface.
type ProjectsGetter interface {
	Projects() ProjectInterface
}

// ProjectInterface has methods to work with Project resources.
type ProjectInterface interface {
	Create(ctx context.Context, project *v1.Project, opts metav1.CreateOptions) (*v1.Project, error)
	Update(ctx context.Context, project *v1.Project, opts metav1.UpdateOptions) (*v1.Project, error)
	// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
	UpdateStatus(ctx context.Context, project *v1.Project, opts metav1.UpdateOptions) (*v1.Project, error)
	Delete(ctx context.Context, name string, opts metav1.DeleteOptions) error
	DeleteCollection(ctx context.Context, opts metav1.DeleteOptions, listOpts metav1.ListOptions) error
	Get(ctx context.Context, name string, opts metav1.GetOptions) (*v1.Project, error)
	List(ctx context.Context, opts metav1.ListOptions) (*v1.ProjectList, error)
	Watch(ctx context.Context, opts metav1.ListOptions) (watch.Interface, error)
	Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts metav1.PatchOptions, subresources ...string) (result *v1.Project, err error)
	Apply(ctx context.Context, project *projectv1.ProjectApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Project, err error)
	// Add a +genclient:noStatus comment above the type to avoid generating ApplyStatus().
	ApplyStatus(ctx context.Context, project *projectv1.ProjectApplyConfiguration, opts metav1.ApplyOptions) (result *v1.Project, err error)
	ProjectExpansion
}

// projects implements ProjectInterface
type projects struct {
	*gentype.ClientWithListAndApply[*v1.Project, *v1.ProjectList, *projectv1.ProjectApplyConfiguration]
}

// newProjects returns a Projects
func newProjects(c *ProjectV1Client) *projects {
	return &projects{
		gentype.NewClientWithListAndApply[*v1.Project, *v1.ProjectList, *projectv1.ProjectApplyConfiguration](
			"projects",
			c.RESTClient(),
			scheme.ParameterCodec,
			"",
			func() *v1.Project { return &v1.Project{} },
			func() *v1.ProjectList { return &v1.ProjectList{} }),
	}
}
