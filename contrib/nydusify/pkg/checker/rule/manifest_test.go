package rule

import (
	"testing"

	"github.com/dragonflyoss/nydus/contrib/nydusify/pkg/parser"
	"github.com/stretchr/testify/assert"

	v1 "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestManifestRuleValidate_IgnoreDeprecatedField(t *testing.T) {
	source := &parser.Parsed{
		NydusImage: &parser.Image{
			Config: v1.Image{
				Config: v1.ImageConfig{
					ArgsEscaped: true, // deprecated field
				},
			},
		},
	}
	target := &parser.Parsed{
		NydusImage: &parser.Image{
			Config: v1.Image{
				Config: v1.ImageConfig{
					ArgsEscaped: false,
				},
			},
		},
	}

	rule := ManifestRule{
		SourceParsed: source,
		TargetParsed: target,
	}

	assert.Nil(t, rule.Validate())
}
