package ecdsa

import (
	"fmt"
	"github.com/consensys/linea-monorepo/prover/crypto/keccak"
	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/common/vector"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/column"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/byte32cmp"
	"github.com/consensys/linea-monorepo/prover/protocol/dedicated/projection"
	"slices"

	//"github.com/consensys/linea-monorepo/prover/protocol/dedicated/projection"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	sym "github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"
	commoncs "github.com/consensys/linea-monorepo/prover/zkevm/prover/common/common_constraints"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/hash/generic"
)

const (
	// Number of columns that represent an address.
	addressColsNumber = 10
	// Number of columns that represent an untrimmed address.
	addressUntrimmedColsNumber = 16
	// Number of columns that represent a hash value in txnData.
	txnDataFromColsNumber = 16
)

// Address submodule is responsible for the columns holding the address of the sender,
// and checking their consistency with the claimed public key
// (since address is the truncated hash of public key).
//
// The addresses comes from two arithmetization modules txn-data and ec-data.
//
// The public-key comes from Gnark-Data.
type Addresses struct {
	addressUntrimmed [addressUntrimmedColsNumber]ifaces.Column
	address          [addressColsNumber]ifaces.Column

	// filters over address columns
	isAddress            ifaces.Column
	isAddressFromEcRec   ifaces.Column
	isAddressFromTxnData ifaces.Column

	// helper columns for intermediate computations/proofs

	// filter over ecRecover; indicating only the AddressHi from EcRecoverIsRes
	// we need this columns just because projection query does not support expressions as filter
	isAddressHiEcRec ifaces.Column
	// a column of all 16 indicating that all 16 bytes of public key should be hashed.
	col16 ifaces.Column

	// used as the hassID for hashing by keccak.
	hashNum ifaces.Column

	// columns for decomposition and trimming the HashHi to AddressHi
	limbColumnsUntrimmed        byte32cmp.LimbColumns
	computeLimbColumnsUntrimmed wizard.ProverAction

	// providers for keccak, Providers contain the inputs and outputs of keccak hash.
	provider generic.GenericByteModule
}

// AddressHi is the trimming of HashHi, taking its last 4bytes.
const trimmingSize = 4

// newAddress creates an Address struct, declaring native columns and the constraints among them.
func newAddress(comp *wizard.CompiledIOP, size int, ecRec *EcRecover, ac *antichamber, td *txnData) *Addresses {
	createCol := createColFn(comp, NAME_ADDRESSES, size)
	ecRecSize := ecRec.EcRecoverIsRes.Size()

	address := [addressColsNumber]ifaces.Column{}
	for i := 0; i < addressColsNumber; i++ {
		address[i] = createCol(fmt.Sprintf("ADDRESS_%d", i))
	}

	addressUntrimmed := [addressUntrimmedColsNumber]ifaces.Column{}
	for i := 0; i < addressUntrimmedColsNumber; i++ {
		addressUntrimmed[i] = createCol(fmt.Sprintf("ADRESS_UNTRIMMED_%d", i))
	}

	// declare the native columns
	addr := &Addresses{
		address:          address,
		addressUntrimmed: addressUntrimmed,
		isAddress:        createCol("IS_ADDRESS"),
		col16: comp.InsertPrecomputed(ifaces.ColIDf("ADDRESS_Col16"),
			smartvectors.NewRegular(vector.Repeat(field.NewElement(16), size))),
		isAddressHiEcRec:     comp.InsertCommit(0, ifaces.ColIDf("ISADRESS_HI_ECREC"), ecRecSize),
		isAddressFromEcRec:   createCol("ISADRESS_FROM_ECREC"),
		isAddressFromTxnData: createCol("ISADRESS_FROM_TXNDATA"),
		hashNum:              createCol("HASH_NUM"),
	}

	td.csTxnData(comp)

	// addresses are fetched from two arithmetization modules (ecRecover and txn-data)
	// IsAddress = IsAdressFromEcRec + IsAdressFromTxnData
	comp.InsertGlobal(0, ifaces.QueryIDf("Format_IsAddress"),
		sym.Sub(addr.isAddress, sym.Add(addr.isAddressFromEcRec, addr.isAddressFromTxnData)))

	commoncs.MustBeBinary(comp, addr.isAddress)
	commoncs.MustBeBinary(comp, addr.isAddressFromEcRec)
	commoncs.MustBeBinary(comp, addr.isAddressFromTxnData)
	commoncs.MustZeroWhenInactive(comp, ac.IsActive,
		addr.isAddress,
		addr.hashNum,
	)

	// check the  trimming of hashHi  to the addressHi
	addr.csAddressTrimming(comp)

	// check that IsAddressHiEcRec is well-formed
	addr.csIsAddressHiEcRec(comp, ecRec)

	// projection from ecRecover to address columns
	// ecdata is already projected over our ecRecover. Thus, we only project from our ecrecover.
	// TODO (Nazarevsky): projection queries to columns
	//projection.InsertProjection(comp, ifaces.QueryIDf("Project_AddressHi_EcRec"),
	//	[]ifaces.Column{ecRec.Limb}, []ifaces.Column{addr.addressHi},
	//	addr.isAddressHiEcRec, addr.isAddressFromEcRec,
	//)
	//
	//projection.InsertProjection(comp, ifaces.QueryIDf("Project_AddressLo_EcRec"),
	//	[]ifaces.Column{ecRec.Limb}, []ifaces.Column{addr.addressLo},
	//	column.Shift(addr.isAddressHiEcRec, -1), addr.isAddressFromEcRec,
	//)
	//
	// projection from txn-data to address columns
	projection.InsertProjection(comp, ifaces.QueryIDf("Project_AddressUntrimmed_TxnData"),
		td.from[:], addressUntrimmed[:],
		td.isFrom, addr.isAddressFromTxnData,
	)

	// impose that hashNum = ac.ID + 1
	comp.InsertGlobal(0, ifaces.QueryIDf("Hash_NUM_IS_ID"),
		sym.Mul(ac.IsActive,
			sym.Sub(addr.hashNum, ac.ID, 1)),
	)
	// assign the keccak provider
	addr.provider = addr.GetProvider(comp, addr.hashNum, ac.UnalignedGnarkData)

	return addr
}

// It checks the well-forming of IsAddressHiEcRec
func (addr *Addresses) csIsAddressHiEcRec(comp *wizard.CompiledIOP, ecRec *EcRecover) {
	// if EcRecoverIsRes[i] == 1 and EcRecover[i+1] == 1 ---> isAddressHiEcRec[i] = 1
	comp.InsertGlobal(0, ifaces.QueryIDf("Is_AddressHi_EcRec_1"),
		sym.Mul(ecRec.EcRecoverIsRes, column.Shift(ecRec.EcRecoverIsRes, 1),
			sym.Sub(1, addr.isAddressHiEcRec)))

	// if EcRecoverIsRes[i] == 0  ---> isAddressHiEcRec[i] = 0
	comp.InsertGlobal(0, ifaces.QueryIDf("Is_AddressHi_EcRec_2"),
		sym.Mul(sym.Sub(1, ecRec.EcRecoverIsRes), addr.isAddressHiEcRec))

	// if EcRecoverIsRes[i] == 1 and EcRecover[i+1] == 0 ---> isAddressHiEcRec[i] = 0
	comp.InsertGlobal(0, ifaces.QueryIDf("Is_AddressHi_EcRec_3"),
		sym.Mul(ecRec.EcRecoverIsRes, sym.Sub(1, column.Shift(ecRec.EcRecoverIsRes, 1)),
			addr.isAddressHiEcRec))
}

// The constraints for trimming the addressUntrimmed to address
func (addr *Addresses) csAddressTrimming(comp *wizard.CompiledIOP) {
	for i := 0; i < addressColsNumber; i++ {
		comp.InsertGlobal(0, ifaces.QueryIDf("Address_Trimming_%d", i), sym.Sub(addr.address[i], addr.addressUntrimmed[i]))
	}
}

// It builds a provider from  public key extracted from Gnark-Data (as hash input) and addresses (as output).
// the consistency check is then deferred to the keccak module.
func (addr *Addresses) GetProvider(comp *wizard.CompiledIOP, id ifaces.Column, uaGnark *UnalignedGnarkData) generic.GenericByteModule {
	// generate a generic byte Module as keccak provider.
	provider := addr.buildGenericModule(id, uaGnark)
	return provider
}

// It builds a GenericByteModule from Address columns and Public-Key/GnarkData columns.
func (addr *Addresses) buildGenericModule(id ifaces.Column, uaGnark *UnalignedGnarkData) (pkModule generic.GenericByteModule) {
	pkModule.Data = generic.GenDataModule{
		HashNum: id,
		Limb:    uaGnark.GnarkData,

		// a column of all 16, since all the bytes of public key are used in hashing
		NBytes: addr.col16,
		Index:  uaGnark.GnarkPublicKeyIndex,
		ToHash: uaGnark.IsPublicKey,
	}

	// TODO (Nazarevsky): this is not correct - we need to change the Hash module
	pkModule.Info = generic.GenInfoModule{
		HashHi:   addr.addressUntrimmed[0],
		HashLo:   addr.address[0],
		IsHashHi: addr.isAddress,
		IsHashLo: addr.isAddress,
	}
	return pkModule
}

// It assigns the native columns specific to the submodule.
func (addr *Addresses) assignAddress(
	run *wizard.ProverRuntime,
	nbEcRecover, size int,
	ac *antichamber,
	ecRec *EcRecover,
	uaGnark *UnalignedGnarkData,
	td *txnData,
) {
	// assign td.isFrom
	td.pa_IsZero.Run(run)

	// assign HashNum
	var (
		one      = field.One()
		id       = ac.ID.GetColAssignment(run).IntoRegVecSaveAlloc()
		isActive = ac.IsActive.GetColAssignment(run).IntoRegVecSaveAlloc()
		hashNum  = common.NewVectorBuilder(addr.hashNum)
	)

	for row := range id {
		if isActive[row].IsOne() {
			f := *new(field.Element).Add(&id[row], &one)
			hashNum.PushField(f)
		} else {
			hashNum.PushInt(0)
		}
	}

	hashNum.PadAndAssign(run)
	addr.assignMainColumns(run, nbEcRecover, size, uaGnark)
	addr.assignHelperColumns(run, ecRec)
}

// It assigns the main columns
func (addr *Addresses) assignMainColumns(
	run *wizard.ProverRuntime,
	nbEcRecover, size int,
	uaGnark *UnalignedGnarkData,
) {
	pkModule := addr.buildGenericModule(addr.hashNum, uaGnark)

	split := splitAt(nbEcRecover)
	n := nbRowsPerEcRec

	streams := pkModule.Data.ScanStreams(run)
	permTrace := keccak.GenerateTrace(streams)

	// Initialize an array of addressUntrimmedColumns limbs columns
	addressUntrimmedColumns := make([][]field.Element, 0, addressUntrimmedColsNumber)
	for i := 0; i < addressUntrimmedColsNumber; i++ {
		addressUntrimmedColumns = append(addressUntrimmedColumns, make([]field.Element, 0, len(permTrace.HashOutPut)))
	}

	// Initialize an array of address limbs columns
	addressColumns := make([][]field.Element, 0, addressColsNumber)
	for i := 0; i < addressColsNumber; i++ {
		addressColumns = append(addressColumns, make([]field.Element, 0, len(permTrace.HashOutPut)))
	}

	isHash := make([]field.Element, 0, len(permTrace.HashOutPut))
	for _, digest := range permTrace.HashOutPut {
		if len(addressColumns[len(addressColumns)-1]) == split {
			n = nbRowsPerTxSign
		}

		// We reverse the digest here, so we can trim the latest (not first) bytes and divide bytes into limbs in
		// the little endian format.

		slices.Reverse(digest[:])

		addressUntrimmed := divideBytes(digest[:])
		for j, limb := range addressUntrimmed {
			// Initialize limb values for each column of addressUntrimmed
			var element field.Element
			element.SetBytes(limb[:])

			repeat := vector.Repeat(element, n)
			addressUntrimmedColumns[j] = append(addressUntrimmedColumns[j], repeat...)
		}

		address := divideBytes(digest[:len(digest)-halfDigest+trimmingSize])
		for j, limb := range address {
			// Initialize limb values for each column of address
			var element field.Element
			element.SetBytes(limb[:])

			repeat := vector.Repeat(element, n)
			addressColumns[j] = append(addressColumns[j], repeat...)
		}

		repeatIsTxHash := vector.Repeat(field.Zero(), n-1)

		isHash = append(isHash, field.One())
		isHash = append(isHash, repeatIsTxHash...)
	}

	isFromEcRec := isHash[:split]
	isFromTxnData := vector.Repeat(field.Zero(), split)
	isFromTxnData = append(isFromTxnData, isHash[split:]...)

	// Assign values to columns

	// We do a reverse of address columns since the address was storing in big-endian format.
	for i := 0; i < addressUntrimmedColsNumber; i++ {
		run.AssignColumn(addr.addressUntrimmed[i].GetColID(), smartvectors.RightZeroPadded(addressUntrimmedColumns[i], size))
	}

	for i := 0; i < addressColsNumber; i++ {
		run.AssignColumn(addr.address[i].GetColID(), smartvectors.RightZeroPadded(addressColumns[i], size))
	}

	run.AssignColumn(addr.isAddress.GetColID(), smartvectors.RightZeroPadded(isHash, size))
	run.AssignColumn(addr.isAddressFromEcRec.GetColID(), smartvectors.RightZeroPadded(isFromEcRec, size))
	run.AssignColumn(addr.isAddressFromTxnData.GetColID(), smartvectors.RightZeroPadded(isFromTxnData, size))
}

// It assigns the helper columns
func (addr *Addresses) assignHelperColumns(run *wizard.ProverRuntime, ecRec *EcRecover) {
	// assign LimbColumns from decomposition via proverAction
	addr.computeLimbColumnsUntrimmed.Run(run)

	// assign isAddressHiEcRec
	isRes := ecRec.EcRecoverIsRes.GetColAssignment(run).IntoRegVecSaveAlloc()
	col := make([]field.Element, len(isRes))
	for i := 0; i < len(isRes); i++ {
		if i < len(isRes)-1 && isRes[i].IsOne() && isRes[i+1].IsOne() {
			col[i] = field.One()
			col[i+1] = field.Zero()
			i = i + 1
		}
	}
	run.AssignColumn(addr.isAddressHiEcRec.GetColID(), smartvectors.NewRegular(col))
}

// It indicates the row where ecrecover and txSignature are split.
func splitAt(nbEcRecover int) int {
	return nbEcRecover * nbRowsPerEcRec
}

func (td *txnData) csTxnData(comp *wizard.CompiledIOP) {

	//  isFrom == 1 iff ct==1
	td.isFrom, td.pa_IsZero = dedicated.IsZero(comp, sym.Sub(td.ct, 1))

	comp.InsertRange(0, ifaces.QueryIDf("Range_FromMostSignificantLimb_TxnData"), td.from[txnDataFromColsNumber-1], 2<<16)
}

// txndata represents the txn_data module from the arithmetization side.
type txnData struct {
	from [txnDataFromColsNumber]ifaces.Column
	ct   ifaces.Column

	// helper column
	isFrom    ifaces.Column
	pa_IsZero wizard.ProverAction
}
