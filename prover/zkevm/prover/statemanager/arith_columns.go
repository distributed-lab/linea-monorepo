package statemanager

import (
	"fmt"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/common"

	"github.com/consensys/linea-monorepo/prover/maths/common/smartvectors"
	"github.com/consensys/linea-monorepo/prover/maths/field"
	"github.com/consensys/linea-monorepo/prover/protocol/column/verifiercol"
	"github.com/consensys/linea-monorepo/prover/protocol/ifaces"
	"github.com/consensys/linea-monorepo/prover/protocol/wizard"
	sym "github.com/consensys/linea-monorepo/prover/symbolic"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/statemanager/mimccodehash"
	"github.com/consensys/linea-monorepo/prover/zkevm/prover/statemanager/statesummary"
)

const (
	ACP             = "acp"
	SCP             = "scp"
	ADDR_MULTIPLIER = "340282366920938463463374607431768211456" // 2^{16*8}
)

// romLex returns the columns of the arithmetization.RomLex module of interest
// to justify the consistency between them and the MiMCCodeHash module
func romLex(comp *wizard.CompiledIOP) *mimccodehash.RomLexInput {
	res := &mimccodehash.RomLexInput{}

	for i := range common.NbLimbU32 {
		res.CFIRomLex[i] = comp.Columns.GetHandle(ifaces.ColIDf("romlex.CODE_FRAGMENT_INDEX_%d", i))
	}

	for i := range common.NbLimbU256 {
		res.CodeHash[i] = comp.Columns.GetHandle(ifaces.ColIDf("romlex.CODE_HASH_%d", i))
	}

	return res
}

// rom returns the columns of the arithmetization corresponding to the Rom module
// that are of interest to justify consistency with the MiMCCodeHash module
func rom(comp *wizard.CompiledIOP) *mimccodehash.RomInput {
	res := &mimccodehash.RomInput{
		NBytes:  comp.Columns.GetHandle("rom.nBYTES"),
		Counter: comp.Columns.GetHandle("rom.COUNTER"),
	}

	for i := range common.NbLimbU128 {
		res.Acc[i] = comp.Columns.GetHandle(ifaces.ColIDf("rom.ACC_%d", i))
	}

	for i := range common.NbLimbU32 {
		res.CFI[i] = comp.Columns.GetHandle(ifaces.ColIDf("rom.CODE_FRAGMENT_INDEX_%d", i))
		res.CodeSize[i] = comp.Columns.GetHandle(ifaces.ColIDf("rom.CODE_SIZE_%d", i))
	}

	return res
}

// acp returns the columns of the arithmetization corresponding to the ACP
// perspective of the Hub that are of interest for checking consistency with
// the stateSummary
func acp(comp *wizard.CompiledIOP) statesummary.HubColumnSet {
	size := comp.Columns.GetHandle("hub.acp_ADDRESS_HI").Size()

	// the prover-side state manager uses a single field element for 20-bytes addresses
	// and we need to create this column ourselves
	if !comp.Columns.Exists("HUB_acp_PROVER_SIDE_ADDRESS_IDENTIFIER") {
		combinedAddr := comp.InsertCommit(0,
			"HUB_acp_PROVER_SIDE_ADDRESS_IDENTIFIER",
			size,
		)

		// constrain the processed HUB addresses
		addrHI := comp.Columns.GetHandle("hub.acp_ADDRESS_HI")
		addrLO := comp.Columns.GetHandle("hub.acp_ADDRESS_LO")
		comp.InsertGlobal(
			0,
			ifaces.QueryIDf("STATE_MANAGER_ACP_HUB_PROCESSED_ADDRESSES_GLOBAL_CONSTRAINT"),
			sym.Sub(
				combinedAddr,
				sym.Mul(
					addrHI,
					field.NewFromString(ADDR_MULTIPLIER),
				),
				addrLO,
			),
		)
	}

	constantZero := verifiercol.NewConstantCol(field.Zero(), size)

	res := statesummary.HubColumnSet{
		Exists:        comp.Columns.GetHandle("hub.acp_EXISTS"),
		ExistsNew:     comp.Columns.GetHandle("hub.acp_EXISTS_NEW"),
		PeekAtAccount: comp.Columns.GetHandle("hub.acp_PEEK_AT_ACCOUNT"),
		PeekAtStorage: constantZero,
		FirstAOC:      comp.Columns.GetHandle("hub.acp_FIRST_IN_CNF"),
		LastAOC:       comp.Columns.GetHandle("hub.acp_FINAL_IN_CNF"),
		FirstKOC:      constantZero,
		LastKOC:       constantZero,
		FirstAOCBlock: comp.Columns.GetHandle("hub.acp_FIRST_IN_BLK"),
		LastAOCBlock:  comp.Columns.GetHandle("hub.acp_FINAL_IN_BLK"),
		FirstKOCBlock: constantZero,
		LastKOCBlock:  constantZero,
	}

	for i := range common.NbLimbEthAddress {
		res.Address[i] = comp.Columns.GetHandle(ifaces.ColIDf("HUB_acp_PROVER_SIDE_ADDRESS_IDENTIFIER_%v", i))
	}

	for i := range common.NbLimbU32 {
		res.AddressHI[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_ADDRESS_HI_%v", i))
		res.DeploymentNumber[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_DEPLOYMENT_NUMBER_%v", i))
		res.DeploymentNumberInf[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_DEPLOYMENT_NUMBER_%v", i)) // Assuming same as DeploymentNumber
		res.MinDeplBlock[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_DEPLOYMENT_NUMBER_FIRST_IN_BLOCK_%v", i))
		res.MaxDeplBlock[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_DEPLOYMENT_NUMBER_FINAL_IN_BLOCK_%v", i))
	}

	for i := range common.NbLimbU128 {
		res.AddressLO[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_ADDRESS_LO_%v", i))
		res.CodeHashHI[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_HASH_HI_%v", i))
		res.CodeHashLO[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_HASH_LO_%v", i))
		res.CodeHashHINew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_HASH_HI_NEW_%v", i))
		res.CodeHashLONew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_HASH_LO_NEW_%v", i))
		res.BalanceOld[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_BALANCE_%v", i))
		res.BalanceNew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_BALANCE_NEW_%v", i))
		res.KeyHI[i] = constantZero
		res.KeyLO[i] = constantZero
		res.ValueHICurr[i] = constantZero
		res.ValueLOCurr[i] = constantZero
		res.ValueHINext[i] = constantZero
		res.ValueLONext[i] = constantZero
	}

	for i := range common.NbLimbU64 {
		res.Nonce[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_NONCE_%v", i))
		res.NonceNew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_NONCE_NEW_%v", i))
		res.CodeSizeOld[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_SIZE_%v", i))
		res.CodeSizeNew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_SIZE_NEW_%v", i))
		res.BlockNumber[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_REL_BLK_NUM_%v", i))
	}

	return res
}

// scp returns the columns of the arithmetization correspoanding to the SCP
// perspective of the Hub that are of interest for checking consistency with
// the stateSummary
func scp(comp *wizard.CompiledIOP) statesummary.HubColumnSet {
	size := comp.Columns.GetHandle("hub.scp_ADDRESS_HI").Size()

	// the prover-side state manager uses a single field element for 20-bytes addresses
	// and we need to create this column ourselves
	if !comp.Columns.Exists("HUB_scp_PROVER_SIDE_ADDRESS_IDENTIFIER") {
		combinedAddr := comp.InsertCommit(0,
			"HUB_scp_PROVER_SIDE_ADDRESS_IDENTIFIER",
			size,
		)

		// constrain the processed HUB addresses
		addrHI := comp.Columns.GetHandle("hub.scp_ADDRESS_HI")
		addrLO := comp.Columns.GetHandle("hub.scp_ADDRESS_LO")
		comp.InsertGlobal(
			0,
			ifaces.QueryIDf("STATE_MANAGER_SCP_HUB_PROCESSED_ADDRESSES_GLOBAL_CONSTRAINT"),
			sym.Sub(
				combinedAddr,
				sym.Mul(
					addrHI,
					field.NewFromString(ADDR_MULTIPLIER),
				),
				addrLO,
			),
		)
	}

	constantZero := verifiercol.NewConstantCol(field.Zero(), size)

	res := statesummary.HubColumnSet{
		Exists:        comp.Columns.GetHandle("hub.acp_EXISTS"),
		ExistsNew:     comp.Columns.GetHandle("hub.acp_EXISTS_NEW"),
		PeekAtAccount: comp.Columns.GetHandle("hub.acp_PEEK_AT_ACCOUNT"),
		PeekAtStorage: constantZero,
		FirstAOC:      comp.Columns.GetHandle("hub.acp_FIRST_IN_CNF"),
		LastAOC:       comp.Columns.GetHandle("hub.acp_FINAL_IN_CNF"),
		FirstKOC:      constantZero,
		LastKOC:       constantZero,
		FirstAOCBlock: comp.Columns.GetHandle("hub.acp_FIRST_IN_BLK"),
		LastAOCBlock:  comp.Columns.GetHandle("hub.acp_FINAL_IN_BLK"),
		FirstKOCBlock: constantZero,
		LastKOCBlock:  constantZero,
	}

	for i := range common.NbLimbEthAddress {
		res.Address[i] = comp.Columns.GetHandle(ifaces.ColIDf("HUB_acp_PROVER_SIDE_ADDRESS_IDENTIFIER_%v", i))
	}

	for i := range common.NbLimbU32 {
		res.AddressHI[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_ADDRESS_HI_%v", i))
		res.DeploymentNumber[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_DEPLOYMENT_NUMBER_%v", i))
		res.DeploymentNumberInf[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_DEPLOYMENT_NUMBER_%v", i)) // Assuming same as DeploymentNumber
		res.MinDeplBlock[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_DEPLOYMENT_NUMBER_FIRST_IN_BLOCK_%v", i))
		res.MaxDeplBlock[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_DEPLOYMENT_NUMBER_FINAL_IN_BLOCK_%v", i))
	}

	for i := range common.NbLimbU128 {
		res.AddressLO[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_ADDRESS_LO_%v", i))
		res.CodeHashHI[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_HASH_HI_%v", i))
		res.CodeHashLO[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_HASH_LO_%v", i))
		res.CodeHashHINew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_HASH_HI_NEW_%v", i))
		res.CodeHashLONew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_HASH_LO_NEW_%v", i))
		res.BalanceOld[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_BALANCE_%v", i))
		res.BalanceNew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_BALANCE_NEW_%v", i))
		res.KeyHI[i] = constantZero
		res.KeyLO[i] = constantZero
		res.ValueHICurr[i] = constantZero
		res.ValueLOCurr[i] = constantZero
		res.ValueHINext[i] = constantZero
		res.ValueLONext[i] = constantZero
	}

	for i := range common.NbLimbU64 {
		res.Nonce[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_NONCE_%v", i))
		res.NonceNew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_NONCE_NEW_%v", i))
		res.CodeSizeOld[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_SIZE_%v", i))
		res.CodeSizeNew[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_CODE_SIZE_NEW_%v", i))
		res.BlockNumber[i] = comp.Columns.GetHandle(ifaces.ColIDf("hub.acp_REL_BLK_NUM_%v", i))
	}

	return res
}

/*
assignHubAddresses is a function that combines addressHI and addressLO from
the arithmetization columns into a single column.
*/
func assignHubAddresses(run *wizard.ProverRuntime) {
	assignHubAddressesSubdomain := func(domainName string) {
		addressHI := run.GetColumn(ifaces.ColID(fmt.Sprintf("hub.%s_ADDRESS_HI", domainName)))
		addressLO := run.GetColumn(ifaces.ColID(fmt.Sprintf("hub.%s_ADDRESS_LO", domainName)))

		size := addressHI.Len()
		newVect := make([]field.Element, size)
		for i := range newVect {
			elemHi := addressHI.Get(i)
			bytesHi := elemHi.Bytes()

			elemLo := addressLO.Get(i)
			bytesLo := elemLo.Bytes()
			newBytes := make([]byte, field.Bytes)
			// set the high part
			for j := 0; j < 4; j++ {
				newBytes[12+j] = bytesHi[32-(4-j)]
			}
			// set the low part
			for j := 4; j < 20; j++ {
				newBytes[12+j] = bytesLo[16+(j-4)]
			}
			newVect[i].SetBytes(newBytes)
		}
		run.AssignColumn(
			ifaces.ColID(fmt.Sprintf("HUB_%s_PROVER_SIDE_ADDRESS_IDENTIFIER", domainName)),
			smartvectors.NewRegular(newVect),
			wizard.DisableAssignmentSizeReduction,
		)
	}
	// assign the addresses column in each of the submodules
	assignHubAddressesSubdomain(ACP)
	assignHubAddressesSubdomain(SCP)
}
