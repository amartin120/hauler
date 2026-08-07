package reference_test

import (
	"reflect"
	"strings"
	"testing"

	"hauler.dev/go/hauler/v2/pkg/reference"
)

func TestParse(t *testing.T) {
	type args struct {
		ref string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{
			name: "Should add hauler namespace when doesn't exist",
			args: args{
				ref: "myfile",
			},
			want:    "hauler/myfile:latest",
			wantErr: false,
		},
		{
			name: "shouldn't modify namespaced reference",
			args: args{
				ref: "rancher/rancher:latest",
			},
			want:    "rancher/rancher:latest",
			wantErr: false,
		},
		{
			name: "Shouldn't modify canonical reference",
			args: args{
				ref: "index.docker.io/library/registry@sha256:42043edfae481178f07aa077fa872fcc242e276d302f4ac2026d9d2eb65b955f",
			},
			want:    "index.docker.io/library/registry@sha256:42043edfae481178f07aa077fa872fcc242e276d302f4ac2026d9d2eb65b955f",
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := reference.Parse(tt.args.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("Parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.Name(), tt.want) {
				t.Errorf("Parse() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestRepoFromBaseRef is a regression test for #667: a digest-only base ref
// (myorg/myimage@sha256:<hex>) must have the "@sha256:<hex>" suffix stripped
// wholesale, not just the last colon (which would otherwise land inside the
// digest itself).
func TestRepoFromBaseRef(t *testing.T) {
	cases := map[string]string{
		"myorg/myimage@sha256:" + strings.Repeat("a", 64):   "myorg/myimage",
		"myorg/myimage:v1.0.2":                              "myorg/myimage",
		"myorg/myimage":                                     "myorg/myimage",
		"nested/path/img@sha256:" + strings.Repeat("b", 64): "nested/path/img",
	}
	for in, want := range cases {
		if got := reference.RepoFromBaseRef(in); got != want {
			t.Errorf("RepoFromBaseRef(%q) = %q, want %q", in, got, want)
		}
	}
}
