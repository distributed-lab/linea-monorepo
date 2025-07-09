package bits

import (
	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
)

// BitDecomposed represents the output of a bit decomposition of
// a column. The struct implements the [wizard.ProverAction] interface
// to self-assign itself.
type BitDecomposed struct {
	// Packed is the input of the bit-decomposition
	Packed []ifaces.Column
	// Bits lists the decomposed bits of the "packed" column in LSbit
	// order.
	Bits                []ifaces.Column
	isPackedLimbNotZero []ifaces.Column
}

// BitDecompose generates a bit decomposition of a column and returns
// a struct that implements the [wizard.ProverAction] interface to
// self-assign itself.
func BitDecompose(comp *wizard.CompiledIOP, packed []ifaces.Column, numBits int) *BitDecomposed {

	var (
		round = packed[0].Round()
		bd    = &BitDecomposed{
			Packed: packed,
			Bits:   make([]ifaces.Column, numBits),
		}
	)

	bitExpr := []*symbolic.Expression{}

	for j := 0; j < numBits; j++ {
		bd.Bits[j] = comp.InsertCommit(round, ifaces.ColIDf("%v_BIT_%v", packed[0].GetColID(), j), packed[0].Size())
		MustBeBoolean(comp, bd.Bits[j])
		bitExpr = append(bitExpr, symbolic.NewVariable(bd.Bits[j]))
	}

	// This constraint ensures that the recombined bits are equal to the
	// original column.
	for i := 0; i < len(packed); i++ {
		bd.isPackedLimbNotZero = append(bd.isPackedLimbNotZero, comp.InsertCommit(round, ifaces.ColIDf("IS_PACKED_NOT_ZERO_%v", i), packed[0].Size()))
	}

	for i := len(packed) - 1; i >= 0; i-- {
		ind := len(packed) - i - 1

		if ind < len(bd.Bits)/16 {
			break
		}

		comp.InsertGlobal(
			round,
			ifaces.QueryIDf("%v_BIT_RECOMBINATION", packed[i].GetColID()),
			symbolic.Mul(
				bd.isPackedLimbNotZero[ind],
				symbolic.Sub(
					packed[i],
					symbolic.NewPolyEval(symbolic.NewConstant(2), bitExpr[ind*16:ind*16+16]),
				),
			),
		)
	}

	return bd
}

// Run implements the [wizard.ProverAction] interface and assigns the bits
// columns
func (bd *BitDecomposed) Run(run *wizard.ProverRuntime) {
	bits := make([][]field.Element, len(bd.Bits))

	// Obtain packed elements from
	var elements [][]field.Element
	for i, packed := range bd.Packed {

		v := packed.GetColAssignment(run)
		var packedElements []field.Element
		var packedElementsIsZero []field.Element

		for colElement := range v.IterateCompact() {
			packedElements = append(packedElements, colElement)

			isPackedLimbNotZero := field.One()
			if colElement.IsZero() {
				isPackedLimbNotZero = field.Zero()
			}

			packedElementsIsZero = append(packedElementsIsZero, isPackedLimbNotZero)
		}

		run.AssignColumn(bd.isPackedLimbNotZero[i].GetColID(), smartvectors.RightZeroPadded(packedElementsIsZero, bd.Packed[0].Size()))

		elements = append(elements, packedElements)
	}

	for i := range elements[0] {
		var el []field.Element
		for j := range elements {
			el = append(el, elements[j][i])
		}

		x := common.CombineElements(el)

		if !x.IsUint64() {
			panic("can handle 64 bits at most")
		}

		xNum := x.Uint64()
		for j := range len(bd.Bits) {
			if xNum>>j&1 == 1 {
				bits[j] = append(bits[j], field.One())
			} else {
				bits[j] = append(bits[j], field.Zero())
			}
		}
	}

	for i, bitCol := range bd.Bits {
		run.AssignColumn(bitCol.GetColID(), smartvectors.FromCompactWithShape(bd.Packed[0].GetColAssignment(run), bits[i]))
	}
}

// MustBeBoolean adds a constraint ensuring that the input is a boolean
// column. The constraint is named after the column.
func MustBeBoolean(comp *wizard.CompiledIOP, col ifaces.Column) {
	// This adds the constraint x^2 = x
	comp.InsertGlobal(
		col.Round(),
		ifaces.QueryID(col.GetColID())+"_IS_BOOLEAN",
		symbolic.Sub(col, symbolic.Mul(col, col)))
}
