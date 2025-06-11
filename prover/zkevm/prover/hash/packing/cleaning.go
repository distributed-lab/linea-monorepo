package packing

import (
	"math/big"

	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/distributed/pragmas"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	sym "github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/consensys/linea-monorepo/prover/utils"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
)

// cleaningInputs collects the inputs of [NewClean] function.
type cleaningInputs struct {
	// It stores Limb-column that is subject to cleaning,
	// given the meaningful number of bytes in nByte-column.
	decomposed decomposition
}

// cleaningCtx stores all the intermediate columns required for imposing the constraints.
// Cleaning module is responsible for cleaning the limbs.
type cleaningCtx struct {
	Inputs *cleaningInputs

	// Columns of values 2^(8*1) or 2^(8*0). In case when we have values like "0x00001200", where
	// last byte is zero, but we need to align to the next byte to have "0x00000012",
	// we construct 2^8 to shift this byte by multiplying 2^8 (or 1 to ignore).
	byteShift []ifaces.Column
	// The column storing the result of the cleaning
	CleanLimb []ifaces.Column
}

// NewClean imposes the constraint for cleaning the limbs.
func NewClean(comp *wizard.CompiledIOP, inp cleaningInputs) cleaningCtx {
	var (
		nbLimbs    = len(inp.decomposed.Inputs.imported.Limb)
		createCol  = common.CreateColFn(comp, CLEANING+"_"+inp.decomposed.Inputs.Name, inp.decomposed.size, pragmas.RightPadded)
		cleanLimbs = make([]ifaces.Column, nbLimbs)
		byteShifts = make([]ifaces.Column, nbLimbs)
	)

	for i := range inp.decomposed.Inputs.imported.Limb {
		cleanLimbs[i] = createCol("CleanLimb_%d", i)
		byteShifts[i] = createCol("Shift_%d", i)
	}

	ctx := cleaningCtx{
		CleanLimb: cleanLimbs,
		Inputs:    &inp,
		byteShift: byteShifts,
	}

	for i := range inp.decomposed.Inputs.imported.Limb {
		shift := byteShifts[i]
		cleanLimb := cleanLimbs[i]
		limb := inp.decomposed.Inputs.imported.Limb[i]
		decomposedLen := inp.decomposed.decomposedLen[i]
		cut := cutColumntExpr(decomposedLen)

		// Constraint that (1 - cut(decomposedLen)) + 2^8 * cut(decomposedLen) == shift
		// this ensures that "shift" is 2^(cut(decomposedLen)) (1 or 2^8)
		comp.InsertGlobal(0, ifaces.QueryIDf("Shift_%d", i),
			sym.Sub(shift, sym.Add(sym.Sub(1, cut), sym.Mul(POWER8, cut))))

		// Check that CleanLimb * shift == Limb
		comp.InsertGlobal(0, ifaces.QueryIDf("LimbCleaning_%v", inp.decomposed.Inputs.Name),
			sym.Sub(sym.Mul(cleanLimb, shift), limb),
		)
	}

	return ctx
}

// assign the native columns
func (ctx *cleaningCtx) Assign(run *wizard.ProverRuntime) {
	var (
		nbLimbs    = len(ctx.Inputs.decomposed.Inputs.imported.Limb)
		cleanLimbs = make([]*common.VectorBuilder, nbLimbs)
		byteShift  = make([]*common.VectorBuilder, nbLimbs)
		limbs      = make([][]field.Element, nbLimbs)
		nByte      = make([][]field.Element, nbLimbs)
	)

	for i := 0; i < nbLimbs; i++ {
		cleanLimbs[i] = common.NewVectorBuilder(ctx.CleanLimb[i])
		byteShift[i] = common.NewVectorBuilder(ctx.byteShift[i])
		limbs[i] = ctx.Inputs.decomposed.Inputs.imported.Limb[i].GetColAssignment(run).IntoRegVecSaveAlloc()
		nByte[i] = ctx.Inputs.decomposed.decomposedLen[i].GetColAssignment(run).IntoRegVecSaveAlloc()
	}

	// populate cleanLimbs
	limbSerialized := [field.Bytes]byte{}
	var f field.Element
	for i := range limbs {
		for pos := range limbs[i] {
			// Extract the limb, which is left aligned to the 16-th byte
			limbSerialized = limbs[i][pos].Bytes()

			nbyte := field.ToInt(&nByte[i][pos])
			res := limbSerialized[LEFT_ALIGNMENT : LEFT_ALIGNMENT+nbyte]
			cleanLimbs[i].PushField(*(f.SetBytes(res)))
		}

		cleanLimbs[i].PadAndAssign(run, field.Zero())
	}

	// populate byteShift
	var (
		shift  field.Element
		power8 = field.NewElement(POWER8)
	)
	for i := range byteShift {
		for pos := range len(limbs[i]) {
			cut := cut(&nByte[pos][i])
			shift.Exp(power8, cut)
			byteShift[i].PushField(shift)
		}

		byteShift[i].PadAndAssign(run, field.Zero())
	}
}

// newCleaningInputs constructs CleaningInputs
func newCleaningInputs(decomposition decomposition) cleaningInputs {
	return cleaningInputs{
		decomposed: decomposition,
	}
}

// cut expects a column of values from range of [0, 2] and returns
// expression of column * (1 - (column - 1)) which maps:
//
// cut(1) = 1
// cut(2) = 0
// cut(0) = 0
func cut(element *field.Element) *big.Int {
	var result, tmp field.Element
	one := field.One()

	tmp.Sub(element, &one)
	result.Mul(element, &tmp)

	// SANITY CHECK that value is either 1 or 0
	if !result.IsOne() && !result.IsZero() {
		utils.Panic("unexpected value after cutting: %s", result)
	}

	return big.NewInt(int64(result.Uint64()))
}

// cutColumntExpr expects a column of values from range of [0, 2] and returns
// expression of column * (1 - (column - 1)) which maps:
//
// cutColumntExpr(1) = 1
// cutColumntExpr(2) = 0
// cutColumntExpr(0) = 0
func cutColumntExpr(column ifaces.Column) *sym.Expression {
	one := sym.NewConstant(1)
	return sym.Mul(column, sym.Sub(one, sym.Sub(column, one)))
}
