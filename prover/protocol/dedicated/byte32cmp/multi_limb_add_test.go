package byte32cmp

import (
	"testing"

	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/compiler/dummy"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/stretchr/testify/require"
)

const max16 = 0xFFFF

type testCase struct {
	name        string
	aVals       [][]int
	bVals       []int
	maskVals    []int
	result      [][]int
	expectError bool
}

func TestAddColToLimbs(t *testing.T) {
	tests := []testCase{
		{
			name: "with_carry",
			aVals: [][]int{
				{0, 0, 0, 0},
				{0, 0, max16, 0},
				{0, max16, max16, 0},
				{max16, max16, max16, 0},
			},
			bVals:    []int{1, 1, 1, 0},
			maskVals: []int{1, 1, 1, 0},
		},
		// Edge cases (all single‐row, 4 limbs each)
		{
			name: "zero_plus_zero",
			aVals: [][]int{
				{0}, {0}, {0}, {0},
			},
			bVals: []int{0},
		},
		{
			name: "max_lsb_plus_one",
			aVals: [][]int{
				{0}, {0}, {0}, {max16},
			},
			bVals: []int{1},
		},
		{
			name: "cascade_carry",
			aVals: [][]int{
				{0}, {max16}, {max16}, {max16},
			},
			bVals: []int{1},
		},
		{
			name: "max_16bit_addition",
			aVals: [][]int{
				{0}, {0}, {0}, {0x8000},
			},
			bVals: []int{0x8000},
		},
		{
			name: "partial_carry",
			aVals: [][]int{
				{0}, {0}, {max16}, {0x8000},
			},
			bVals: []int{0x8000},
		},
		// multiple rows
		{
			name: "multi_row_4",
			aVals: [][]int{
				{0, 0x1234, 0, 0},
				{0, 0x5678, 0x5678, 0},
				{0, 0x9ABC, 0x9ABC, 0},
				{0, 0xDEF0, 0xDEF0, 1},
			},
			bVals: []int{0, 1, 1, max16},
		},
		{
			name: "multi_row_2",
			aVals: [][]int{
				{0, 0x1234, 0, 0},
				{0, 0x5678, 0x5678, 1},
			},
			bVals: []int{0, 1, 1, max16},
		},
		{
			name: "multi_row_8",
			aVals: [][]int{
				{0, 0x1234, 0, 0},
				{0, 0x5678, 0x5678, 0},
				{0, 0x9ABC, 0x9ABC, 0},
				{0, 0xDEF0, 0xDEF0, 0},
				{0, 0x1111, 0x1111, 0},
				{0, 0x2222, 0x2222, 0},
				{0, 0x3333, 0x3333, 0},
				{0, 0x4444, 0x4444, 1},
			},
			bVals: []int{0, 1, 1, max16},
		},
		// single limb
		{
			name: "single_limb",
			aVals: [][]int{
				{100, 0xFFFE, 0, 0x7FFF},
			},
			bVals: []int{50, 1, 0, 0x7FFF},
		},
		// overflow cases
		{
			name:        "overflow_not_allowed",
			aVals:       [][]int{{max16}},
			bVals:       []int{1},
			expectError: true,
		},
		{
			name:        "overflow_multilimb_not_allowed",
			aVals:       [][]int{{max16}, {max16}, {max16}, {max16}},
			bVals:       []int{1},
			expectError: true,
		},
		// with precomputed result
		{
			name: "with_precomputed_result",
			aVals: [][]int{
				{0, 0, 0, 0},
				{0, 0, max16, 0},
				{0, max16, max16, 0},
				{max16, max16, max16, 0},
			},
			bVals:    []int{1, 1, 1, 0},
			maskVals: []int{1, 1, 1, 0},
			result: [][]int{
				{0, 0, 1, 0},
				{0, 1, 0, 0},
				{1, 0, 0, 0},
				{0, 0, 0, 0},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			testAddColToLimbs(t, tc)
		})
	}
}

func testAddColToLimbs(t *testing.T, tc testCase) {
	var pa wizard.ProverAction

	define := func(builder *wizard.Builder) {
		comp := builder.CompiledIOP

		numRows := len(tc.aVals[0])

		aLimbs := LimbColumns{
			Limbs:       make([]ifaces.Column, len(tc.aVals)),
			LimbBitSize: 16,
			IsBigEndian: true,
		}

		for i := range tc.aVals {
			aLimbs.Limbs[i] = comp.InsertCommit(0, ifaces.ColIDf("A%d", i), numRows)
		}

		bCol := comp.InsertCommit(0, "B", numRows)

		var maskCol ifaces.Column
		if tc.maskVals != nil {
			maskCol = comp.InsertCommit(0, "MASK", numRows)
		} else {
			maskCol = comp.InsertPrecomputed("MASK", smartvectors.NewConstant(field.One(), numRows))
		}

		var result LimbColumns
		if tc.result != nil {
			result = LimbColumns{
				Limbs:       make([]ifaces.Column, len(tc.result)),
				LimbBitSize: 16,
				IsBigEndian: true,
			}

			for i := range tc.aVals {
				result.Limbs[i] = comp.InsertCommit(0, ifaces.ColIDf("R%d", i), numRows)
			}
		}

		_, pa = NewAddColToLimbs(comp, &AddColToLimbsIn{
			Name:   tc.name,
			ALimbs: aLimbs,
			B:      bCol,
			Mask:   symbolic.NewVariable(maskCol),
			Result: result,
		})
	}

	prover := func(run *wizard.ProverRuntime) {
		for i, vals := range tc.aVals {
			run.AssignColumn(ifaces.ColIDf("A%d", i), smartvectors.ForTest(vals...))
		}

		run.AssignColumn("B", smartvectors.ForTest(tc.bVals...))

		if tc.maskVals != nil {
			run.AssignColumn("MASK", smartvectors.ForTest(tc.maskVals...))
		}

		if tc.result != nil {
			for i, vals := range tc.result {
				run.AssignColumn(ifaces.ColIDf("R%d", i), smartvectors.ForTest(vals...))
			}
		}

		pa.Run(run)
	}

	comp := wizard.Compile(define, dummy.Compile)
	proof := wizard.Prove(comp, prover)
	err := wizard.Verify(comp, proof)

	if tc.expectError {
		require.Error(t, err)
	} else {
		require.NoError(t, err)
	}
}
