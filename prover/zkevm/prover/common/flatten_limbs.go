package common

import (
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/column"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/projection"
)

const (
	// NbFlattenColLimbs defines the default number of columns allocated for storing the limbs.
	NbFlattenColLimbs = 8
)

// FlattenColumn flattens multiple limb columns and an accompanying mask into single columns,
// provides consistency checks via a precomputed projection mask.
type FlattenColumn struct {
	// Limbs is the row-wise concatenation of all limb columns.
	Limbs ifaces.Column
	// Mask is the row-wise concatenation of the original mask column.
	Mask ifaces.Column
	// auxProjectionMask selects flattenLimbs's positions to validate flattening consistency.
	auxProjectionMask ifaces.Column
	// originalLimbs holds the original limb columns to flatten.
	originalLimbs []ifaces.Column
	// originalMask holds the original mask column that selects elements for gnark circuit.
	originalMask ifaces.Column
	// size is the expected length of the flattened columns.
	size        int
	module      string
	nbLimbsCols int
}

// NewFlattenColumn initializes a FlattenColumn with:
// 	- flattenSize: output column length
// 	- nbLimbsCols: number of limb columns to flatten
// 	- module: prefix for column identifiers
// It commits placeholders for flattened limbs and mask, and precomputes the projection mask.
func NewFlattenColumn(comp *wizard.CompiledIOP, flattenSize, nbLimbsCols int, module string) *FlattenColumn {
	flattenMask := comp.InsertCommit(0, ifaces.ColIDf("%s.FLATTEN_MASK", module), flattenSize)
	flattenLimbs := comp.InsertCommit(0, ifaces.ColIDf("%s.FLATTEN_LIMBS", module), flattenSize)
	auxProjectionMask := comp.InsertPrecomputed(ifaces.ColIDf("%s.AUX_PROJECTION_MASK", module),
		precomputeAuxProjectionMask(flattenSize, nbLimbsCols))

	return &FlattenColumn{
		Limbs:             flattenLimbs,
		Mask:              flattenMask,
		auxProjectionMask: auxProjectionMask,
		size:              flattenSize,
		module:            module,
	}
}

// CsEcDataProjection adds projection constraints to verify flattened limbs and mask
// align with original columns, using the auxiliary projection mask.
func (l *FlattenColumn) CsEcDataProjection(comp *wizard.CompiledIOP, limbs []ifaces.Column, mask ifaces.Column) {
	masks := make([]ifaces.Column, l.nbLimbsCols)
	shiftedFlattenLimbs := make([]ifaces.Column, l.nbLimbsCols)
	shiftedFlattenCsEcAdd := make([]ifaces.Column, l.nbLimbsCols)

	for i := 0; i < l.nbLimbsCols; i++ {
		masks[i] = mask
		shiftedFlattenLimbs[i] = column.Shift(l.Limbs, i)
		shiftedFlattenCsEcAdd[i] = column.Shift(l.Mask, i)
	}

	projection.InsertProjection(comp, ifaces.QueryIDf("%v_PROJECT_ECDATA", l.module),
		append(shiftedFlattenLimbs[:], shiftedFlattenCsEcAdd[:]...),
		append(limbs[:], masks[:]...),
		l.auxProjectionMask, mask,
	)

	l.originalMask = mask
	l.originalLimbs = limbs
}

// Assign maps trace limb columns and mask into the flattened columns.
func (l *FlattenColumn) Assign(run *wizard.ProverRuntime) {
	limbsCols := make([][]field.Element, l.size)
	for i, limb := range l.originalLimbs {
		limbsCols[i] = limb.GetColAssignment(run).IntoRegVecSaveAlloc()
	}

	maskCol := l.originalMask.GetColAssignment(run).IntoRegVecSaveAlloc()

	flattenLimbs := NewVectorBuilder(l.Limbs)
	flattenMask := NewVectorBuilder(l.Mask)
	for i := 0; i < len(maskCol); i++ {
		for j := 0; j < l.nbLimbsCols; j++ {
			flattenLimbs.PushField(limbsCols[j][i])
			flattenMask.PushField(maskCol[i])
		}
	}

	flattenLimbs.PadAndAssign(run, field.Zero())
	flattenMask.PadAndAssign(run, field.Zero())
}

// precomputeAuxProjectionMask creates a SmartVector with total size `size`,
// where `nbMasked` positions are periodically set to one.
func precomputeAuxProjectionMask(size, period int) smartvectors.SmartVector {
	resSlice := make([]field.Element, size)

	for i := 0; i < size; i += period {
		resSlice[i].SetOne()
	}

	return smartvectors.NewRegular(resSlice)
}
