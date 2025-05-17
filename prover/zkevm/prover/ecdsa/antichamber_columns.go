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
	return append(
		[]ifaces.Column{ec.EcRecoverID},
		append(
			ec.Limb[:],
			ec.SuccessBit, ec.EcRecoverIndex, ec.EcRecoverIsData, ec.EcRecoverIsRes,
		)...,
	)
}

func (ad *Addresses) cols() []ifaces.Column {
	return append(ad.addressUntrimmed[:], ad.address[:]...)
}

func (ts *txSignature) cols() []ifaces.Column {
	return append([]ifaces.Column{ts.isTxHash}, ts.txHash[:]...)
}

func (ugd *UnalignedGnarkData) cols() []ifaces.Column {
	return append(
		[]ifaces.Column{ugd.IsPublicKey, ugd.GnarkIndex},
		ugd.GnarkData[:]...,
	)
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
		TxHash:     ac.txHash,
	}
}
