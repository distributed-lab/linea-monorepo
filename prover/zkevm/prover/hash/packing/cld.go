package packing

import (
	"math/big"

	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	iszero "github.com/consensys/linea-monorepo/prover/protocol/dedicated"
	"github.com/consensys/linea-monorepo/prover/protocol/distributed/pragmas"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	sym "github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/consensys/linea-monorepo/prover/utils"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
	commonconstraints "github.com/consensys/linea-monorepo/prover/zkevm/prover/common/common_constraints"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/generic"
)

const (
	// Number of columns in decomposedLen and decomposedLenPowers values.
	// This is the number of slices that the NByte is decomposed into, but +1
	// is added for lane repacking stage.
	nbDecomposedLen = common.NbLimbU128 + 1
)

// It stores the inputs for [newDecomposition] function.
type decompositionInputs struct {
	// parameters for decomposition,
	// the are used to determine the number of slices and their lengths.
	param    generic.HashingUsecase
	Name     string
	lookup   lookUpTables
	imported Importation
}

// Decomposition struct stores all the intermediate columns required to constraint correct decomposition.
// Decomposition module is responsible for decomposing the cleanLimbs into
// slices of different sizes.
// The max bytes pushed into a slice is
//
//	min (laneSizeBytes, remaining bytes from the limb)
type decomposition struct {
	Inputs *decompositionInputs
	// decomposedLimbs is the "decomposition" of input Limbs.
	decomposedLimbs []ifaces.Column
	//  the length associated with decomposedLimbs
	decomposedLen []ifaces.Column
	// decomposedLenPowers = 2^(8*decomposedLen)
	decomposedLenPowers []ifaces.Column
	// carry is used to carry the remainder during decomposition
	carry []ifaces.Column
	// it indicates the active part of the decomposition module
	isActive ifaces.Column
	// The filter is obtained from decomposedLen.
	// filter = 1 iff decomposedLen != 0.
	filter []ifaces.Column
	//  the result and  the ProverAction for IsZero().
	resIsZero []ifaces.Column
	paIsZero  []wizard.ProverAction
	// size of the module
	size int
}

/*
newDecomposition defines the columns and constraints asserting to the following facts:

 1. decomposedLimbs is the decomposition of cleanLimbs

 2. decomposedLimbs is of length decomposedLen
*/
func newDecomposition(comp *wizard.CompiledIOP, inp decompositionInputs) decomposition {

	var (
		size = inp.imported.Limb[0].Size()
	)

	decomposed := decomposition{
		Inputs: &inp,
		size:   size,
		// the next assignment guarantees that isActive is from the Activation form.
		isActive: inp.imported.IsActive,
	}

	// Declare the columns
	decomposed.insertCommit(comp)

	for j := range nbDecomposedLen {
		// since they are later used for building the  decomposed.filter.
		commonconstraints.MustZeroWhenInactive(comp, decomposed.isActive, decomposed.decomposedLen[j])
		// this guarantees that filter and decompodedLimbs full fill the same constrains.
	}

	// Declare the constraints
	decomposed.csFilter(comp)
	decomposed.csDecomposLen(comp, inp.imported)
	decomposed.csDecomposedLimbs(comp, inp.imported)

	return decomposed
}

// declare the native columns
func (decomposed *decomposition) insertCommit(comp *wizard.CompiledIOP) {
	createCol := common.CreateColFn(comp, DECOMPOSITION+"_"+decomposed.Inputs.Name, decomposed.size, pragmas.RightPadded)
	for x := range nbDecomposedLen {
		decomposed.decomposedLimbs = append(decomposed.decomposedLimbs, createCol("Decomposed_Limbs_%v", x))
		decomposed.decomposedLen = append(decomposed.decomposedLen, createCol("Decomposed_Len_%v", x))
		decomposed.decomposedLenPowers = append(decomposed.decomposedLenPowers, createCol("Decomposed_Len_Powers_%v", x))
	}

	// carry has less columns than decomposedLimbs (see decomposition implementation).
	for x := range nbDecomposedLen - 1 {
		decomposed.carry = append(decomposed.carry, createCol("Carry_%v", x))
	}

	decomposed.paIsZero = make([]wizard.ProverAction, nbDecomposedLen)
	decomposed.resIsZero = make([]ifaces.Column, nbDecomposedLen)
	decomposed.filter = make([]ifaces.Column, nbDecomposedLen)
	for j := range nbDecomposedLen {
		decomposed.filter[j] = createCol("Filter_%v", j)
	}

}

// /  Constraints over the form of decomposedLen and decomposedLenPowers;
//   - decomposedLen over a row adds up to NBytes
//   - decomposedLenPowers = 2^(8*decomposedLen)
func (decomposed *decomposition) csDecomposLen(
	comp *wizard.CompiledIOP,
	imported Importation,
) {

	lu := decomposed.Inputs.lookup
	// The rows of decomposedLen adds up to NByte; \sum_i decomposedLen[i]=NByte
	s := sym.NewConstant(0)
	for j := range decomposed.decomposedLimbs {
		s = sym.Add(s, decomposed.decomposedLen[j])

		// Equivalence of "decomposedLenPowers" with "2^(decomposedLen * 8)"
		comp.InsertInclusion(0,
			ifaces.QueryIDf("%v_Decomposed_Len_Powers_%v", decomposed.Inputs.Name, j), []ifaces.Column{lu.colNumber, lu.colPowers},
			[]ifaces.Column{decomposed.decomposedLen[j], decomposed.decomposedLenPowers[j]})
	}
	// \sum_i decomposedLen[i]=NByte
	comp.InsertGlobal(0, ifaces.QueryIDf("%v_DecomposedLen_IsNByte", decomposed.Inputs.Name), sym.Sub(s, imported.NByte))
}

// Constraints over the form of decomposedLimbs;
//
// - (decomposedLimbs[0] * 2^8 + carry[0] - Limbs[0]) * decompositionHappened == 0 // base case
// - (decomposedLimbs[i] * 2^8 + carry[i] - Limbs[i] - carry[i-1] * decomposedLenPowers[i]) * decompositionHappened == 0 // for i > 0
// - (decomposedLimbs[last] - carry[last-1]) * decompositionHappened == 0
func (decomposed decomposition) csDecomposedLimbs(
	comp *wizard.CompiledIOP,
	imported Importation,
) {
	var (
		decompositionHappened = decompositionHappened(decomposed.decomposedLen)
		decomposedLimbs       = decomposed.decomposedLimbs
		carry                 = decomposed.carry
		limbs                 = imported.Limb
		last                  = nbDecomposedLen - 1
	)

	// Base case
	comp.InsertGlobal(0, ifaces.QueryIDf("%v_DecomposedLimbs_0", decomposed.Inputs.Name),
		sym.Mul(
			sym.Sub(
				sym.Add(
					sym.Mul(decomposedLimbs[0], sym.NewConstant(POWER8)),
					carry[0],
				), limbs[0]),
			decompositionHappened,
		))

	// For columns 1 to last-1
	for i := 1; i < last-1; i++ {
		comp.InsertGlobal(0, ifaces.QueryIDf("%v_DecomposedLimbs_%v", decomposed.Inputs.Name, i),
			sym.Mul(
				sym.Sub(
					sym.Add(
						sym.Mul(decomposedLimbs[i], sym.NewConstant(POWER8)),
						carry[i],
					),
					limbs[i],
					sym.Mul(carry[i-1], decomposed.decomposedLenPowers[i]),
				),
				decompositionHappened,
			))
	}

	// Last column
	comp.InsertGlobal(0, ifaces.QueryIDf("%v_DecomposedLimbs_Last", decomposed.Inputs.Name),
		sym.Mul(
			sym.Sub(
				decomposedLimbs[last],
				carry[last-1],
			),
			decompositionHappened,
		),
	)

	// range checks
	for i := range decomposedLimbs {
		comp.InsertRange(0, ifaces.QueryIDf("%v_DecomposedLimbs_RangeCheck_%v", decomposed.Inputs.Name, i),
			decomposedLimbs[i], POWER16)
	}
	for i := range carry {
		comp.InsertRange(0, ifaces.QueryIDf("%v_Carry_RangeCheck_%v", decomposed.Inputs.Name, i),
			carry[i], POWER8)
	}
}

// /  Constraints over the form of filter and decomposedLen;
//   - filter = 1 iff decomposedLen != 0
func (decomposed decomposition) csFilter(comp *wizard.CompiledIOP) {
	// filtre = 1 iff decomposedLen !=0
	for j := range nbDecomposedLen {
		// s.resIsZero = 1 iff decomposedLen = 0
		decomposed.resIsZero[j], decomposed.paIsZero[j] = iszero.IsZero(comp, decomposed.decomposedLen[j])
		// s.filter = (1 - s.resIsZero), this enforces filters to be binary.
		comp.InsertGlobal(0, ifaces.QueryIDf("%v_%v_%v", decomposed.Inputs.Name, "IS_NON_ZERO", j),
			sym.Sub(decomposed.filter[j],
				sym.Sub(1, decomposed.resIsZero[j])),
		)
	}

	// filter[0] = 1 over is Active.
	// this ensures that the first slice of the limb falls in the first column.
	comp.InsertGlobal(0, ifaces.QueryIDf("%v_FIRST_SLICE_IN_FIRST_COLUMN", decomposed.Inputs.Name),
		sym.Sub(
			decomposed.filter[0], decomposed.isActive),
	)

}

// assign the columns specific to the module.
func (decomposed *decomposition) Assign(run *wizard.ProverRuntime) {
	decomposed.assignMainColumns(run)

	// assign s.filter
	for j := range nbDecomposedLen {
		decomposed.paIsZero[j].Run(run)

		var (
			filter        = decomposed.filter[j]
			compactFilter = make([]field.Element, 0)
			a             = decomposed.resIsZero[j].GetColAssignment(run)
			one           = field.One()
		)

		for ai := range a.IterateCompact() {
			var f field.Element
			f.Sub(&one, &ai)
			compactFilter = append(compactFilter, f)
		}

		run.AssignColumn(filter.GetColID(), smartvectors.FromCompactWithShape(a, compactFilter))
	}
}

// it builds the inputs for [newDecomposition]
func getDecompositionInputs(pckParam PackingInput, lookup lookUpTables) decompositionInputs {
	decInp := decompositionInputs{
		param:    pckParam.PackingParam,
		Name:     pckParam.Name,
		imported: pckParam.Imported,
		lookup:   lookup,
	}
	return decInp
}

// it assigns the main columns (not generated via an inner ProverAction)
func (decomposed *decomposition) assignMainColumns(run *wizard.ProverRuntime) {
	var (
		imported = decomposed.Inputs.imported
		nByte    = imported.NByte.GetColAssignment(run)

		// Assign the columns decomposedLimbs and decomposedLen
		decomposedLen = make([][]field.Element, nbDecomposedLen)
		// Assign decomposed decomposedLimbs, carru
		decomposedLimbs, carry [][]field.Element
		// Construct decomposedNByte for later use
		decomposedNByte = decomposeNByte(nByte.IntoRegVecSaveAlloc())
		limbs           = make([][]field.Element, len(imported.Limb))

		// These are needed for sanity-checking the implementation which
		// crucially relies on the fact that the input vectors are post-padded.
		nByteStartRange, _ = smartvectors.CoWindowRange(nByte)
	)

	if nByteStartRange > 0 {
		utils.Panic("the implementation relies on the fact that the input vectors are post-padded, but their range start after 0, range-start:[%v]", nByteStartRange)
	}

	for i, limb := range imported.Limb {
		limbs[i] = limb.GetColAssignment(run).IntoRegVecSaveAlloc()
	}

	// assign row-by-row
	decomposedLen = cutUpToMax(nByte, nbDecomposedLen, MAXNBYTE)

	for j := range decomposedLen {
		run.AssignColumn(decomposed.decomposedLen[j].GetColID(), smartvectors.RightZeroPadded(decomposedLen[j], decomposed.size))
	}

	// powersOf256 stores the successive powers of 2^8=256. This is used to compute
	// the decomposedLenPowers = 2^(8*i).
	powersOf256 := make([]field.Element, MAXNBYTE+1)
	for i := range powersOf256 {
		powersOf256[i].Exp(field.NewElement(POWER8), big.NewInt(int64(i)))
	}

	// assign decomposedLenPowers
	for j := range decomposedLen {
		decomposedLenPowers := make([]field.Element, len(decomposedLen[j]))
		for i := range decomposedLen[j] {
			decomLen := field.ToInt(&decomposedLen[j][i])
			decomposedLenPowers[i] = powersOf256[decomLen]
		}
		run.AssignColumn(decomposed.decomposedLenPowers[j].GetColID(),
			smartvectors.RightPadded(decomposedLenPowers, field.One(), decomposed.size))
	}

	// asign decomposedLimbs and carry
	decomposedLimbs, carry = decomposeLimbsAndCarry(limbs, decomposedLen, decomposedNByte)
	for i := range decomposedLimbs {
		run.AssignColumn(decomposed.decomposedLimbs[i].GetColID(),
			smartvectors.RightZeroPadded(decomposedLimbs[i], decomposed.size))
	}
	for i := range carry {
		run.AssignColumn(decomposed.carry[i].GetColID(),
			smartvectors.RightZeroPadded(carry[i], decomposed.size))
	}
}

// It receives an (set of) integer number N and outputs (n_1,...,n_nbChunk) such that
// N = \sum_{i < nbChunk} n_i
// n_i = min ( max, N - \sum_{j<i} n_j)
func cutUpToMax(nByte smartvectors.SmartVector, nbChunk, max int) [][]field.Element {

	var (
		missing = uint64(max)
		b       = make([][]field.Element, nbChunk)
	)

	for curr := range nByte.IterateSkipPadding() {

		// a is filled with nbChunk elements. Theses elements are the decomposition
		// of 'curr' into of integers less or equal to "max". For instance, curr = 10
		// and max=3 would give a and nChunk=5 would give a = [3, 3, 3, 1, 0].
		//
		// missing is a sort of carry that propagate the remainder of the decomposition
		// to the next line. With our example, the missing value would be 2 at the end
		// of the decomposition. And the next line would start with a 2 and then keep
		// going with 3s.
		var a = make([]uint64, 0, nbChunk)
		curr := curr.Uint64()
		for curr != 0 {
			if curr >= missing {
				a = append(a, missing)
				curr = curr - missing
				missing = uint64(max)
			} else {
				a = append(a, curr)
				missing = missing - curr
				curr = 0
			}
		}

		for len(a) < nbChunk {
			a = append(a, 0)
		}

		for j := 0; j < nbChunk; j++ {
			b[j] = append(b[j], field.NewElement(a[j]))
		}
	}

	return b
}

// decomposeNByte decomposes a number of meaningful bytes into array of meaningful
// bytes per each limb.
//
// Assumption here, that all bytes to the left from the current one are filled, until
// zero one is found.
func decomposeNByte(nbytes []field.Element) [][]int {
	decomposed := make([][]int, common.NbLimbU128)
	for i := range decomposed {
		decomposed[i] = make([]int, len(nbytes))
	}

	for i, nbyte := range nbytes {
		leftBytes := nbyte.Uint64()

		for j := range common.NbLimbU128 {
			if leftBytes > MAXNBYTE {
				decomposed[j][i] = int(MAXNBYTE)
				leftBytes -= MAXNBYTE
			} else {
				decomposed[j][i] = int(leftBytes)
				break
			}
		}
	}

	return decomposed
}

// decomposeHappened returns an expression that indicates whether the decomposition happened in this row.
//
// We assume that decomposition happened whenether the first column of number meaningful bytes is 1
// and second one is not zero.
//
// f(x) = x (2 - x) ==> f(x) = 1 iff x = 1 as x \in [0, 2].
// g(y) = y (3 - y) ==> g(1) = 2, g(2) = 2, g(0) = 0
//
// z(x, y) = f(x) * g(y) = x (2 - x) * y (3 - y)
func decompositionHappened(decomposedLen []ifaces.Column) *sym.Expression {
	if len(decomposedLen) == 0 {
		utils.Panic("decompositionHappened expects at least one decomposedLen column")
	}

	x := decomposedLen[0]
	y := decomposedLen[1]

	f := sym.Mul(
		x,
		sym.Sub(
			sym.NewConstant(2),
			x,
		),
	)
	g := sym.Mul(
		y,
		sym.Sub(
			sym.NewConstant(3),
			y,
		),
	)
	z := sym.Mul(f, g)
	return z
}

// decomposeLimbsAndCarry constructs decomposed limbs and carry from original limbs.
//
// For example, assume we have a limbs: [0x0000a1c1, 0x0000a2c2, 0x0000a3c3],
// nbyte = 6 (nbytes here is [2, 2, 2]), but decomposedLen = [1, 2, 2, 1], so we
// need to shift it and create a carry column:
//
// [0x000000a1, 0x0000c1a2, 0x0000c2a3, 0x000000c3] (a.k.a decomposedLimbs)
// [1         , 2          , 2        , 1] (a.k.a decomposedLimbs)
// [0x000000c1, 0x000000c2, 0x000000c3] (a.k.a carry)
// [0x0000a1c1, 0x0000a2c2, 0x0000a3c3] (a.k.a Limbs)
func decomposeLimbsAndCarry(limbs, decomposedLen [][]field.Element, nbytes [][]int) (decomposedLimbs, carry [][]field.Element) {
	nbRows := len(decomposedLen[0])

	// Initialize decomposedLimbs and carry
	decomposedLimbs = make([][]field.Element, nbDecomposedLen)
	carry = make([][]field.Element, nbDecomposedLen-1)

	for i := range nbDecomposedLen {
		decomposedLimbs[i] = make([]field.Element, nbRows)
		if i < nbDecomposedLen-1 {
			carry[i] = make([]field.Element, nbRows)
		}
	}

	for row := range nbRows {
		decompositionHappened := decomposedLen[0][row].Uint64() == 1 && decomposedLen[1][row].Uint64() != 0
		// don't need to decompose, just copy from original limb with last one as zero
		if !decompositionHappened {
			for i := range common.NbLimbU128 {
				meaningful := meaningfulBytes(nbytes, limbs, row, i)
				decomposedLimbs[i][row].SetBytes(meaningful)
				// carry is already set as zeros
			}
			continue
		}

		// Collect all meaningful bytes in a row, so it's easier to take what we need.
		allMeaningfullBytes := make([]byte, 0, nbDecomposedLen*MAXNBYTE)
		for i := range common.NbLimbU128 {
			meaningful := meaningfulBytes(nbytes, limbs, row, i)
			allMeaningfullBytes = append(allMeaningfullBytes, meaningful...)

			// carry is always the last byte of the original limb if nbyte is 2
			if nbytes[i][row] == 2 {
				carry[i][row].SetBytes([]byte{meaningful[len(meaningful)-1]})
			}
		}

		// Decompose the collected bytes into meaningful bytes for each decomposed limb.
		var taken uint64 = 0
		for i := range nbDecomposedLen {
			bytes := decomposedLen[i][row].Uint64()
			decomposedLimbs[i][row].SetBytes(allMeaningfullBytes[taken : taken+bytes])
			taken += bytes
		}
	}
	return decomposedLimbs, carry
}

// meaningfulBytes returns the meaningful bytes of a field elemen by index
func meaningfulBytes(nbytes [][]int, limbs [][]field.Element, row, i int) []byte {
	nbyte := nbytes[i][row]
	limbSerialized := limbs[i][row].Bytes()
	meaningful := limbSerialized[LEFT_ALIGNMENT : LEFT_ALIGNMENT+nbyte]
	return meaningful
}
