package mimccodehash

import (
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/query"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
)

// inputModules is an optional sub-component of [Module] collecting the columns
// of the Rom and the RomLew module. It is optional in the sense that it may
// be omitted in tests but it is not optional in production.
type inputModules struct {
	RomInput    *RomInput
	RomLexInput *RomLexInput
}

// This function checks if the codehash module properly takes inputs from the
// Rom and RomLex module via a projection and two lookup queries
//
// @alex: since this module cannot currently be assigned without running this
// we should perhaps make this part of the main [NewModule] constructor as it
// is not actually optional.
func (mch *Module) ConnectToRom(comp *wizard.CompiledIOP,
	romInput *RomInput,
	romLexInput *RomLexInput) *Module {

	romInput.complete(comp)

	var colA []ifaces.Column
	colA = append(colA, romInput.CFI)
	colA = append(colA, romInput.Acc[:]...)
	colA = append(colA, romInput.CodeSize[:]...)

	var colB []ifaces.Column
	colB = append(colB, mch.CFI)
	colB = append(colB, mch.Limb[:]...)
	colB = append(colB, mch.CodeSize[:]...)

	// Projection query between romInput and MiMCCodeHash module
	comp.InsertProjection(
		ifaces.QueryIDf("PROJECTION_ROM_MIMC_CODE_HASH_%v", mch.inputs.Name),
		query.ProjectionInput{ColumnA: colA,
			ColumnB: colB,
			FilterA: romInput.CounterIsEqualToNBytesMinusOne,
			FilterB: mch.IsActive})

	// Lookup between romLexInput and mch for
	// {CFI, codeHash}
	comp.InsertInclusion(0,
		ifaces.QueryIDf("LOOKUP_MIMC_CODE_HASH_ROMLEX_%v", mch.inputs.Name),
		append([]ifaces.Column{mch.CFI}, mch.CodeHash[:]...),
		append([]ifaces.Column{romLexInput.CFIRomLex}, romLexInput.CodeHash[:]...))

	// And the reverse lookup
	comp.InsertInclusion(0,
		ifaces.QueryIDf("LOOKUP_ROMLEX_MIMC_CODE_HASH_%v", mch.inputs.Name),
		append([]ifaces.Column{romLexInput.CFIRomLex}, romLexInput.CodeHash[:]...),
		append([]ifaces.Column{mch.CFI}, mch.CodeHash[:]...))

	mch.inputModules = &inputModules{
		RomInput:    romInput,
		RomLexInput: romLexInput,
	}

	return mch
}
