package execution_data_collector

import (
	"fmt"
	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/column"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/query"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	sym "github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
	commonconstraints "github.com/consensys/linea-monorepo/prover/zkevm/prover/common/common_constraints"
	util "github.com/consensys/linea-monorepo/prover/zkevm/prover/publicInput/utilities"
)

type MIMCHasher struct {
	// a typical isActive binary column, provided as an input to the module
	isActive ifaces.Column
	// the data to be hashed, this column is provided as an input to the module
	inputData      ifaces.Column
	inputIsActive  ifaces.Column
	data           [common.NbLimbU256]ifaces.Column
	isData         ifaces.Column //isActive * canBeData
	isDataFirstRow *dedicated.HeartBeatColumn
	isDataOddRows  *dedicated.HeartBeatColumn
	// this column stores the MiMC hashes
	hash [common.NbLimbU256]ifaces.Column
	// a constant column that stores the last relevant value of the hash
	HashFinal [common.NbLimbU256]ifaces.Column
	// state is an intermediary column used to enforce the MiMC constraints
	state [common.NbLimbU256]ifaces.Column
}

func NewMIMCHasher(comp *wizard.CompiledIOP, inputData, inputIsActive ifaces.Column, name string) *MIMCHasher {
	size := 2 * inputData.Size()
	res := &MIMCHasher{
		inputData:     inputData,
		inputIsActive: inputIsActive,
		isActive:      util.CreateCol(name, "ACTIVE", size, comp),
		isData:        util.CreateCol(name, "IS_DATA", size, comp),
	}

	for i := range res.hash {
		res.data[i] = util.CreateCol(name, fmt.Sprintf("DATA_%d", i), size, comp)
		res.hash[i] = util.CreateCol(name, fmt.Sprintf("HASH_%d", i), size, comp)
		res.HashFinal[i] = util.CreateCol(name, fmt.Sprintf("HASH_FINAL_%d", i), size, comp)
		res.state[i] = util.CreateCol(name, fmt.Sprintf("STATE_%d", i), size, comp)
	}

	res.isDataFirstRow = dedicated.CreateHeartBeat(comp, 0, size, 0, res.isActive)
	res.isDataOddRows = dedicated.CreateHeartBeat(comp, 0, 2, 1, res.isActive)
	return res
}

func DefineHashFilterConstraints(comp *wizard.CompiledIOP, hasher *MIMCHasher, name string) {

	// we require that isActive is binary in DefineIndicatorsMustBeBinary
	// require that the isActive filter only contains 1s followed by 0s
	comp.InsertGlobal(
		0,
		ifaces.QueryIDf("%s_IS_ACTIVE_CONSTRAINT_NO_0_TO_1", name),
		sym.Sub(
			hasher.isActive,
			sym.Mul(
				column.Shift(hasher.isActive, -1),
				hasher.isActive,
			),
		),
	)
	util.MustBeBinary(comp, hasher.isActive)

	comp.InsertGlobal(
		0,
		ifaces.QueryIDf("%s_IS_DATA", name),
		sym.Sub(
			hasher.isData,
			hasher.isDataFirstRow.Natural,
			hasher.isDataOddRows.Natural,
		),
	)
	util.MustBeBinary(comp, hasher.isData)
}

// DefineHasher defines the constraints of the MIMCHasher.
// Its isActive and data columns are assumed to be already constrained in another module, no need to constrain them again.
func (hasher *MIMCHasher) DefineHasher(comp *wizard.CompiledIOP, name string) {

	// MiMC constraints
	comp.InsertMiMC(0, ifaces.QueryIDf("%s_%s", name, "MIMC_CONSTRAINT"), hasher.data, hasher.state, hasher.hash, nil)

	for i := range hasher.hash {
		// intermediary state integrity
		comp.InsertGlobal(0, ifaces.QueryIDf("%s_CONSISTENCY_STATE_AND_HASH_LAST_%d", name, i), // LAST is either hashSecond
			sym.Add(
				sym.Mul(
					hasher.isData,
					sym.Sub(hasher.state[i],
						column.Shift(hasher.hash[i], -1),
					),
				),
				sym.Mul(
					sym.Sub(1, hasher.isData),
					sym.Sub(hasher.state[i],
						0,
					),
				),
			),
		)

		// LAST is either hashSecond
		comp.InsertGlobal(0, ifaces.QueryIDf("%s_CONSISTENCY_STATE_AND_HASH_LAST_2_%d", name, i),
			sym.Mul(
				hasher.isActive,
				sym.Sub(1, hasher.isData),
				sym.Sub(hasher.data[i],
					column.Shift(hasher.hash[i], -1),
				),
			),
		)

		// state, the current state column, is initially zero
		comp.InsertLocal(0, ifaces.QueryIDf("%s_INTER_LOCAL_%d", name, i),
			ifaces.ColumnAsVariable(hasher.state[i]),
		)

		// constrain HashFinal
		commonconstraints.MustBeConstant(comp, hasher.HashFinal[i])
		util.CheckLastELemConsistency(comp, hasher.isActive, hasher.hash[i], hasher.HashFinal[i], name)
	}

	// constraint isActive
	DefineHashFilterConstraints(comp, hasher, name)

	comp.InsertProjection(
		ifaces.QueryIDf("%s_%s", name, "PROJECTION_DATA"),
		query.ProjectionInput{
			ColumnA: []ifaces.Column{hasher.data[common.NbLimbU256-1]}, // input data is the last limb of the data column
			ColumnB: []ifaces.Column{hasher.inputData},
			FilterA: hasher.isData,
			FilterB: hasher.inputIsActive,
		},
	)

	// Check that the data column is zero for all but the last limb
	for i := 0; i < common.NbLimbU256-1; i++ {
		comp.InsertGlobal(0, ifaces.QueryIDf("%s_DATA_ZERO_LIMBS_AT_INPUT_%d", name, i),
			sym.Mul(hasher.isData, hasher.data[i]),
		)
	}
}

// AssignHasher assigns the data in the MIMCHasher. The data and isActive columns are fetched from another module.
func (hasher *MIMCHasher) AssignHasher(run *wizard.ProverRuntime) {

	var (
		state, hash, data [common.NbLimbU256]*common.VectorBuilder

		inputSize = hasher.inputData.Size()
		isData    = common.NewVectorBuilder(hasher.isData)
		isActive  = common.NewVectorBuilder(hasher.isActive)
	)

	for i := range state {
		state[i] = common.NewVectorBuilder(hasher.state[i])
		hash[i] = common.NewVectorBuilder(hasher.hash[i])
		data[i] = common.NewVectorBuilder(hasher.data[i])

		// the initial state is zero
		state[i].PushZero()
	}

	// Helper function to perform BlockCompression and update hash
	var prevState, dataToHash [common.NbLimbU256]field.Element
	performBlockCompression := func(isDataVal field.Element) {
		isData.PushField(isDataVal)
		isActive.PushOne()

		for i := range prevState {
			prevState[i] = state[i].Last()
			dataToHash[i] = data[i].Last()
		}

		dataHash := common.BlockCompression(prevState[:], dataToHash[:])
		for i := range hash {
			hash[i].PushField(dataHash[i])
		}
	}

	// Helper to push data with only the last limb set
	pushDataWithLastLimb := func(value field.Element) {
		for i := 0; i < common.NbLimbU256-1; i++ {
			dataToHash[i].SetZero()
		}

		dataToHash[common.NbLimbU256-1] = value
		for i := range data {
			data[i].PushField(dataToHash[i])
		}
	}

	// Writing the first row
	pushDataWithLastLimb(hasher.inputData.GetColAssignmentAt(run, 0))
	performBlockCompression(field.One())

	// Assign the state for the next hashing
	for i := range state {
		state[i].PushField(hash[i].Last())
	}

	// Writing the second row
	pushDataWithLastLimb(hasher.inputData.GetColAssignmentAt(run, 1))
	performBlockCompression(field.One())

	// Process remaining rows
	for j := 2; j < inputSize; j++ {
		inputIsActive := hasher.inputIsActive.GetColAssignmentAt(run, j)
		if inputIsActive.IsZero() {
			break
		}

		// Odd rows: start a new hash from zero, using the previous hash as data
		for i := range state {
			state[i].PushZero()
			data[i].PushField(hash[i].Last())
		}
		performBlockCompression(field.Zero())

		// Even rows: continue the hash by adding the input data
		for i := range state {
			state[i].PushField(hash[i].Last())
		}
		pushDataWithLastLimb(hasher.inputData.GetColAssignmentAt(run, j))
		performBlockCompression(field.One())
	}

	zeroLimbs := []field.Element{field.Zero()}
	zeroHash := common.BlockCompression(zeroLimbs, zeroLimbs) // scalar

	// Assign the hasher columns
	isData.PadAndAssign(run, field.Zero())
	isActive.PadAndAssign(run, field.Zero())
	for i := range hash {
		// The order is important here, we assign the final hash, and then pad and assign the hash column
		run.AssignColumn(hasher.HashFinal[i].GetColID(), smartvectors.NewConstant(hash[i].Last(), hasher.HashFinal[i].Size()))

		state[i].PadAndAssign(run, field.Zero())
		data[i].PadAndAssign(run, field.Zero())
		hash[i].PadAndAssign(run, zeroHash[i])
	}

	hasher.isDataFirstRow.Assign(run)
	hasher.isDataOddRows.Assign(run)
}
