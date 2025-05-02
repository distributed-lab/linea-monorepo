package ecdsa

import (
	"fmt"
	"github.com/consensys/linea-monorepo/prover/crypto/keccak"
	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/common/vector"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/column"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	sym "github.com/consensys/linea-monorepo/prover/symbolic"
	commonconstraints "github.com/consensys/linea-monorepo/prover/zkevm/prover/common/common_constraints"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/generic"
)

const NB_TX_HASH_COLS = 16

// TxSignature is responsible for assigning the relevant columns for transaction-Hash,
// and checking their consistency with the data coming from rlp_txn.
//
// columns for transaction-hash are native columns,
//
// columns for rlp-txn lives on the arithmetization side.
type txSignature struct {
	Inputs   *txSignatureInputs
	txHash   [NB_TX_HASH_COLS]ifaces.Column
	isTxHash ifaces.Column

	// provider for keccak, Provider contains the inputs and outputs of keccak hash.
	provider generic.GenericByteModule
}

type txSignatureInputs struct {
	RlpTxn generic.GenDataModule
	ac     *antichamber
}

func newTxSignatures(comp *wizard.CompiledIOP, inp txSignatureInputs) *txSignature {
	var createCol = createColFn(comp, NAME_TXSIGNATURE, inp.ac.size)

	var txHashCols [NB_TX_HASH_COLS]ifaces.Column
	for i := 0; i < NB_TX_HASH_COLS; i++ {
		txHashCols[i] = createCol(fmt.Sprintf("TX_HASH_%d", i))
	}

	var (
		res = &txSignature{
			txHash:   txHashCols,
			isTxHash: createCol("TX_IS_HASH_HI"),

			Inputs: &inp,
		}
	)

	commonconstraints.MustBeBinary(comp, res.isTxHash)

	// isTxHash = 1 if isFeching = 1 and Source = 1
	comp.InsertGlobal(0, ifaces.QueryIDf("IS_TX_HASH"),
		sym.Mul(inp.ac.IsFetching, inp.ac.Source,
			sym.Sub(1, res.isTxHash),
		),
	)

	// txHashHi remains the same between two fetchings.
	var subExpressions []any
	for i := 0; i < NB_TX_HASH_COLS; i++ {
		subExpressions = append(subExpressions, sym.Sub(res.txHash[i], column.Shift(res.txHash[i], -1)))
	}

	comp.InsertGlobal(0, "txHash_REMAIN_SAME",
		sym.Mul(inp.ac.IsActive,
			sym.Sub(1, inp.ac.IsFetching),
			sym.Add(subExpressions...)),
	)

	// txHash most significant limb is below 2**16
	comp.InsertRange(0, "Range_txHash_MostSignificantLimb",
		res.txHash[NB_TX_HASH_COLS-1], 2<<16)

	res.provider = res.GetProvider(comp, inp.RlpTxn)

	return res
}

// It builds a provider from rlp-txn (as hash input) and native columns of TxSignature (as hash output)
// the consistency check is then deferred to the keccak module.
func (txn *txSignature) GetProvider(comp *wizard.CompiledIOP, rlpTxn generic.GenDataModule) generic.GenericByteModule {
	provider := generic.GenericByteModule{}

	// pass rlp-txn as DataModule.
	provider.Data = rlpTxn

	// generate infoModule from native columns
	provider.Info = txn.buildInfoModule()

	return provider
}

// it builds an infoModule from native columns
func (txn *txSignature) buildInfoModule() generic.GenInfoModule {
	// TODO (Nazarevsky): this is not correct - we need to change the Hash module
	info := generic.GenInfoModule{
		HashHi:   txn.txHash[0],
		HashLo:   txn.txHash[0],
		IsHashHi: txn.isTxHash,
		IsHashLo: txn.isTxHash,
	}
	return info
}

// it assign the native columns
func (txn *txSignature) assignTxSignature(run *wizard.ProverRuntime, nbActualEcRecover int) {

	var (
		nbEcRecover = nbActualEcRecover
		n           = startAt(nbEcRecover)
		isTxHash    = vector.Repeat(field.Zero(), n)
		size        = txn.Inputs.ac.size
		permTrace   = keccak.GenerateTrace(txn.Inputs.RlpTxn.ScanStreams(run))
		hashColumns [NB_TX_HASH_COLS][]field.Element
	)

	for i := 0; i < NB_TX_HASH_COLS; i++ {
		hashColumns[i] = vector.Repeat(field.Zero(), n)
	}

	for _, digest := range permTrace.HashOutPut {
		hashLimbs := divideBytes(digest[:])
		for j, limb := range hashLimbs {
			// Initialize limb values for each column of txHash
			var element field.Element
			element.SetBytes(limb[:])

			repeat := vector.Repeat(element, nbRowsPerTxSign)
			hashColumns[j] = append(hashColumns[j], repeat...)
		}

		repeatIsTxHash := vector.Repeat(field.Zero(), nbRowsPerTxSign-1)

		isTxHash = append(isTxHash, field.One())
		isTxHash = append(isTxHash, repeatIsTxHash...)
	}

	for i := 0; i < NB_TX_HASH_COLS; i++ {
		run.AssignColumn(txn.txHash[i].GetColID(), smartvectors.RightZeroPadded(hashColumns[i], size))
	}

	run.AssignColumn(txn.isTxHash.GetColID(), smartvectors.RightZeroPadded(isTxHash, size))
}

func startAt(nbEcRecover int) int {
	return nbEcRecover * nbRowsPerEcRec
}
