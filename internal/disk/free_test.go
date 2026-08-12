package disk

import (
	"math"
	"testing"
)

func TestAvailableBytes(t *testing.T) {
	tests := []struct {
		name      string
		blocks    uint64
		blockSize int64
		want      int64
		wantErr   bool
	}{
		{name: "zero", blocks: 0, blockSize: 4096},
		{name: "product", blocks: 3, blockSize: 4096, want: 12288},
		{name: "largest exact product", blocks: math.MaxInt64, blockSize: 1, want: math.MaxInt64},
		{name: "overflow saturates", blocks: math.MaxUint64, blockSize: 4096, want: math.MaxInt64},
		{name: "zero block size", blocks: 1, wantErr: true},
		{name: "negative block size", blocks: 1, blockSize: -1, wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := availableBytes("test", test.blocks, test.blockSize)
			if (err != nil) != test.wantErr {
				t.Fatalf("availableBytes error=%v wantErr=%t", err, test.wantErr)
			}

			if got != test.want {
				t.Fatalf("availableBytes=%d want %d", got, test.want)
			}
		})
	}
}

func TestFreeBytes(t *testing.T) {
	_, err := FreeBytes(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
}
