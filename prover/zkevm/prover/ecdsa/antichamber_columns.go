package ecdsa

import "github.com/consensys/linea-monorepo/prover/protocol/ifaces"

func (ac *antichamber) cols(withActive bool) []ifaces.Column {
	res := []ifaces.Column{
		ac.ID,
		ac.IsPushing,
		ac.IsFetching,
		ac.Source,
	}
	if withActive {
		res = append(res, ac.IsActive)
	}
	return res
}

func (ec *EcRecover) cols() []ifaces.Column {
	return []ifaces.Column{
		ec.EcRecoverID,
		ec.Limb,
		ec.SuccessBit,
		ec.EcRecoverIndex,
		ec.EcRecoverIsData,
		ec.EcRecoverIsRes,
	}
}

func (ad *Addresses) cols() []ifaces.Column {
	var cols []ifaces.Column

	cols = append(cols, ad.addressUntrimmed[:]...)
	cols = append(cols, ad.address[:]...)

	return cols
}

func (ts *txSignature) cols() []ifaces.Column {
	var columns = []ifaces.Column{
		ts.isTxHash,
	}

	columns = append(columns, ts.txHash[:]...)

	return columns
}

func (ugd *UnalignedGnarkData) cols() []ifaces.Column {
	return []ifaces.Column{
		ugd.IsPublicKey,
		ugd.GnarkIndex,
		ugd.GnarkData,
	}
}

func (ac *antichamber) unalignedGnarkDataSource() *unalignedGnarkDataSource {
	// TODO: change unalignedGnarkDataSource
	return &unalignedGnarkDataSource{
		IsActive:   ac.IsActive,
		IsPushing:  ac.IsPushing,
		IsFetching: ac.IsFetching,
		Source:     ac.Source,
		Limb:       ac.EcRecover.Limb,
		SuccessBit: ac.EcRecover.SuccessBit,
		IsData:     ac.EcRecover.EcRecoverIsData,
		IsRes:      ac.EcRecover.EcRecoverIsRes,
		TxHashHi:   ac.txSignature.txHash[0],
		TxHashLo:   ac.txSignature.txHash[0],
	}
}
