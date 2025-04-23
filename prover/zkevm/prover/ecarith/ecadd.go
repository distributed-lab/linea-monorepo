package ecarith

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/plonk"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/projection"
	"github.com/consensys/linea-monorepo/prover/protocol/column"
	"github.com/consensys/gnark/std/math/emulated"
	"fmt"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/algebra"
)

const (
	NAME_ECADD = "ECADD_INTEGRATION"
)

const (
	nbRowsPerEcAdd = 12
	// nbLimbsCols defines the number of columns allocated for storing the limbs.
	nbLimbsCols  = 8
	nbTotalLimbs = nbRowsPerEcAdd * nbLimbsCols
)

// EcAdd integrated EC_ADD precompile call verification inside a
// gnark circuit.
type EcAdd struct {
	*EcDataAddSource
	AlignedGnarkData *plonk.Alignment

	// flattenLimbs is all the limbs' columns flattened into a single column.
	flattenLimbs      ifaces.Column
	auxProjectionMask ifaces.Column

	size int
	*Limits
}

func NewEcAddZkEvm(comp *wizard.CompiledIOP, limits *Limits) *EcAdd {
	src := &EcDataAddSource{
		CsEcAdd: comp.Columns.GetHandle("ecdata.CIRCUIT_SELECTOR_ECADD"),
		Index:   comp.Columns.GetHandle("ecdata.INDEX"),
		IsData:  comp.Columns.GetHandle("ecdata.IS_ECADD_DATA"),
		IsRes:   comp.Columns.GetHandle("ecdata.IS_ECADD_RESULT"),
	}

	for i := 0; i < nbLimbsCols; i++ {
		src.Limbs[i] = comp.Columns.GetHandle(ifaces.ColIDf("ecdata.LIMB_%d", i))
	}

	return newEcAdd(
		comp,
		limits,
		src,
		[]plonk.Option{plonk.WithRangecheck(16, 6, true)},
	)
}

// newEcAdd creates a new EC_ADD integration.
func newEcAdd(comp *wizard.CompiledIOP, limits *Limits, src *EcDataAddSource, plonkOptions []plonk.Option) *EcAdd {
	size := limits.sizeEcAddIntegration()
	flattenLimbsSize := size * nbLimbsCols

	flattenLimbsCol := comp.InsertCommit(0, "ecdata.ECADD_FLATTEN_LIMBS", flattenLimbsSize)

	toAlign := &plonk.CircuitAlignmentInput{
		Name:  NAME_ECADD + "_ALIGNMENT",
		Round: ROUND_NR,
		DataToCircuitMask: comp.InsertPrecomputed("ecdata.DATA_TO_CIRCUIT_MASK",
			precomputeDataToCircuitMask(limits.NbCircuitInstances*nbTotalLimbs, flattenLimbsSize)),
		DataToCircuit:      flattenLimbsCol,
		Circuit:            NewECAddCircuit(limits),
		NbCircuitInstances: limits.NbCircuitInstances,
		PlonkOptions:       plonkOptions,
		InputFiller:        nil, // not necessary: 0 * (0,0) = (0,0) with complete arithmetic
	}

	res := &EcAdd{
		EcDataAddSource:  src,
		AlignedGnarkData: plonk.DefineAlignment(comp, toAlign),
		flattenLimbs:     flattenLimbsCol,
		auxProjectionMask: comp.InsertPrecomputed("ecdata.AUX_PROJECTION_MASK",
			precomputeAuxProjectionMask(flattenLimbsSize, limits.NbCircuitInstances*nbRowsPerEcAdd, nbLimbsCols)),
		size: size,
	}

	res.csEcDataProjection(comp)

	return res
}

// Assign assigns the data from the trace to the gnark inputs.
func (em *EcAdd) Assign(run *wizard.ProverRuntime) {
	var limbsCols [nbLimbsCols][]field.Element

	for i, limbs := range em.Limbs {
		limbsCols[i] = limbs.GetColAssignment(run).IntoRegVecSaveAlloc()
	}

	flattenLimbs := common.NewVectorBuilder(em.flattenLimbs)
	for i := 0; i < em.Limbs[0].Size(); i++ {
		for j := 0; j < nbLimbsCols; j++ {
			flattenLimbs.PushField(limbsCols[j][i])
		}
	}

	flattenLimbs.PadAndAssign(run, field.Zero())

	em.AlignedGnarkData.Assign(run)
}

// EcDataAddSource is a struct that holds the columns that are used to
// fetch data from the EC_DATA module from the arithmetization.
type EcDataAddSource struct {
	CsEcAdd ifaces.Column
	Limbs   [nbLimbsCols]ifaces.Column
	Index   ifaces.Column
	IsData  ifaces.Column
	IsRes   ifaces.Column
}

// MultiECAddCircuit is a circuit that can handle multiple EC_ADD instances. The
// length of the slice Instances should corresponds to the one defined in the
// Limits struct.
type MultiECAddCircuit struct {
	Instances []ECAddInstance
}

type ECAddInstance struct {
	// First input to addition
	P_X_hi, P_X_lo [nbLimbsCols]frontend.Variable `gnark:",public"`
	P_Y_hi, P_Y_lo [nbLimbsCols]frontend.Variable `gnark:",public"`

	// Second input to addition
	Q_X_hi, Q_X_lo [nbLimbsCols]frontend.Variable `gnark:",public"`
	Q_Y_hi, Q_Y_lo [nbLimbsCols]frontend.Variable `gnark:",public"`

	// The result of the addition. Is provided non-deterministically by the
	// caller, we have to ensure that the result is correct.
	R_X_hi, R_X_lo [nbLimbsCols]frontend.Variable `gnark:",public"`
	R_Y_hi, R_Y_lo [nbLimbsCols]frontend.Variable `gnark:",public"`
}

// NewECAddCircuit creates a new circuit for verifying the EC_MUL precompile
// based on the defined number of inputs.
func NewECAddCircuit(limits *Limits) *MultiECAddCircuit {
	return &MultiECAddCircuit{
		Instances: make([]ECAddInstance, limits.NbInputInstances),
	}
}

func (c *MultiECAddCircuit) Define(api frontend.API) error {

	f, err := emulated.NewField[sw_bn254.BaseField](api)
	if err != nil {
		return fmt.Errorf("field emulation: %w", err)
	}

	// gnark circuit works with 64 bits values, we need to split the 128 bits
	// values into high and low parts.
	nbInstances := len(c.Instances)
	Ps := make([]sw_bn254.G1Affine, nbInstances)
	Qs := make([]sw_bn254.G1Affine, nbInstances)
	Rs := make([]sw_bn254.G1Affine, nbInstances)
	for i := range c.Instances {

		PXlimbs := make([]frontend.Variable, 4)
		PXlimbs[2], PXlimbs[3] = bitslice.Partition(api, c.Instances[i].P_X_hi, 64, bitslice.WithNbDigits(128))
		PXlimbs[0], PXlimbs[1] = bitslice.Partition(api, c.Instances[i].P_X_lo, 64, bitslice.WithNbDigits(128))
		PX := f.NewElement(PXlimbs)
		PYlimbs := make([]frontend.Variable, 4)
		PYlimbs[2], PYlimbs[3] = bitslice.Partition(api, c.Instances[i].P_Y_hi, 64, bitslice.WithNbDigits(128))
		PYlimbs[0], PYlimbs[1] = bitslice.Partition(api, c.Instances[i].P_Y_lo, 64, bitslice.WithNbDigits(128))
		PY := f.NewElement(PYlimbs)
		P := sw_bn254.G1Affine{
			X: *PX,
			Y: *PY,
		}

		QXlimbs := make([]frontend.Variable, 4)
		QXlimbs[2], QXlimbs[3] = bitslice.Partition(api, c.Instances[i].Q_X_hi, 64, bitslice.WithNbDigits(128))
		QXlimbs[0], QXlimbs[1] = bitslice.Partition(api, c.Instances[i].Q_X_lo, 64, bitslice.WithNbDigits(128))
		QX := f.NewElement(QXlimbs)
		QYlimbs := make([]frontend.Variable, 4)
		QYlimbs[2], QYlimbs[3] = bitslice.Partition(api, c.Instances[i].Q_Y_hi, 64, bitslice.WithNbDigits(128))
		QYlimbs[0], QYlimbs[1] = bitslice.Partition(api, c.Instances[i].Q_Y_lo, 64, bitslice.WithNbDigits(128))
		QY := f.NewElement(QYlimbs)
		Q := sw_bn254.G1Affine{
			X: *QX,
			Y: *QY,
		}

		RXlimbs := make([]frontend.Variable, 4)
		RXlimbs[2], RXlimbs[3] = bitslice.Partition(api, c.Instances[i].R_X_hi, 64, bitslice.WithNbDigits(128))
		RXlimbs[0], RXlimbs[1] = bitslice.Partition(api, c.Instances[i].R_X_lo, 64, bitslice.WithNbDigits(128))
		RX := f.NewElement(RXlimbs)
		RYlimbs := make([]frontend.Variable, 4)
		RYlimbs[2], RYlimbs[3] = bitslice.Partition(api, c.Instances[i].R_Y_hi, 64, bitslice.WithNbDigits(128))
		RYlimbs[0], RYlimbs[1] = bitslice.Partition(api, c.Instances[i].R_Y_lo, 64, bitslice.WithNbDigits(128))
		RY := f.NewElement(RYlimbs)
		R := sw_bn254.G1Affine{
			X: *RX,
			Y: *RY,
		}
		Ps[i] = P
		Qs[i] = Q
		Rs[i] = R
	}

	curve, err := algebra.GetCurve[sw_bn254.ScalarField, sw_bn254.G1Affine](api)
	if err != nil {
		panic(err)
	}
	for i := range Rs {
		res := curve.AddUnified(&Ps[i], &Qs[i])
		curve.AssertIsEqual(&Rs[i], res)
	}
	return nil
}

func (em *EcAdd) csEcDataProjection(comp *wizard.CompiledIOP) {
	var shiftedFlattenCols [nbLimbsCols]ifaces.Column
	for i := 0; i < nbLimbsCols; i++ {
		shiftedFlattenCols[i] = column.Shift(em.flattenLimbs, i)
	}

	projection.InsertProjection(comp, ifaces.QueryIDf("%v_PROJECT_ECDATA", NAME_ECADD),
		shiftedFlattenCols[:], em.Limbs[:],
		em.auxProjectionMask, em.CsEcAdd,
	)
}

// precomputeDataToCircuitMask creates and returns a SmartVector with the first `masked` elements
// set to one and the rest as zero.
func precomputeDataToCircuitMask(masked int, size int) smartvectors.SmartVector {
	resSlice := make([]field.Element, size)

	for i := 0; i < masked; i++ {
		resSlice[i].SetOne()
	}

	return smartvectors.NewRegular(resSlice)
}

// precomputeAuxProjectionMask creates a SmartVector with total size `size`,
// where `nbMasked` positions are periodically set to one.
func precomputeAuxProjectionMask(size, nbMasked, period int) smartvectors.SmartVector {
	resSlice := make([]field.Element, size)

	for i := 0; i < nbMasked; i++ {
		resSlice[i*period].SetOne()
	}

	return smartvectors.NewRegular(resSlice)
}
