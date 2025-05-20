package prover

import (
	"github.com/consensys/linea-monorepo/prover/protocol/compiler/dummy"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	"github.com/consensys/linea-monorepo/prover/utils"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/ecarith"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/ecdsa"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/ecpair"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/generic"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/modexp"
	"testing"
)

type makeTestCase struct {
	HashNum []int
	ToHash  []int
}

var testCaseEcdsa = makeTestCase{
	HashNum: []int{1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2},
	ToHash:  []int{1, 1, 1, 0, 0, 0, 1, 0, 1, 1, 1, 1},
}

func TestMultipleModules(t *testing.T) {
	ct, names, err := readFile("testdata/multiple_modules.csv")
	if err != nil {
		t.Fatal(err)
	}

	ecdsaLimits := &ecdsa.Settings{
		MaxNbEcRecover:     3,
		MaxNbTx:            2,
		NbInputInstance:    5,
		NbCircuitInstances: 1,
	}

	ecaddLimits := &ecarith.Limits{
		NbInputInstances:   1,
		NbCircuitInstances: 1,
	}

	ecmulLimits := &ecarith.Limits{
		NbInputInstances:   3,
		NbCircuitInstances: 2,
	}

	ecpairLimits := &ecpair.Limits{
		NbMillerLoopInputInstances:   5,
		NbFinalExpInputInstances:     1,
		NbG2MembershipInputInstances: 5,
		NbMillerLoopCircuits:         1,
		NbFinalExpCircuits:           1,
		NbG2MembershipCircuits:       1,
	}

	modexpLimits := modexp.Settings{
		MaxNbInstance256:  1,
		MaxNbInstance4096: 1,
	}

	nbRowsPerTxInTxnData := 3

	var ecdsaZk *ecdsa.EcdsaZkEvm
	var ecAdd *ecarith.EcAdd
	var ecMul *ecarith.EcMul
	var ecPair *ecpair.ECPair
	var modexpMod *modexp.Module

	var rlpTxn generic.GenDataModule

	size := utils.NextPowerOfTwo(ct.Len())

	cmp := wizard.Compile(
		func(b *wizard.Builder) {
			comp := b.CompiledIOP

			rlpTxn = createGenDataModule(comp, "rlptxn", size)
			commit(comp, names, size)

			ecMul = ecarith.NewEcMulZkEvm(comp, ecmulLimits)
			ecAdd = ecarith.NewEcAddZkEvm(comp, ecaddLimits)
			ecPair = ecpair.NewECPairZkEvm(comp, ecpairLimits)
			modexpMod = modexp.NewModuleZkEvm(comp, modexpLimits)
			ecdsaZk = ecdsa.NewEcdsaZkEvm(comp, ecdsaLimits)
		},
		dummy.Compile,
	)

	proof := wizard.Prove(cmp,
		func(run *wizard.ProverRuntime) {
			assignEcdsa(run, &rlpTxn, testCaseEcdsa, ecdsaLimits, size, nbRowsPerTxInTxnData)

			ct.Assign(run, names...)

			ecdsaZk.Assign(run, dummyTxSignatureGetter, ecdsaLimits.MaxNbTx)
			ecMul.Assign(run)
			ecAdd.Assign(run)
			ecPair.Assign(run)
			modexpMod.Assign(run)
		})

	if err := wizard.Verify(cmp, proof); err != nil {
		t.Fatal("proof failed", err)
	}
}
