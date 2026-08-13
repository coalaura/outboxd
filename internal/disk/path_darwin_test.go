package disk

import (
	"path/filepath"
	"testing"
)

func TestValidatePathAllowsDarwinSystemAlias(t *testing.T) {
	root := filepath.Join("/var", "folders")

	err := ValidatePath(root)
	if err != nil {
		t.Fatal(err)
	}
}
