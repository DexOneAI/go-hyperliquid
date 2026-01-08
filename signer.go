package hyperliquid

import (
	"context"
	"crypto/ecdsa"
	"dexone/pkg/signer"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"github.com/google/uuid"
)

type Signer interface {
	SignTypedData(ctx context.Context, typedData apitypes.TypedData) (*SignatureResult, error)
}

type SignerMaster interface {
	CreateSigner(ctx context.Context, address string) Signer
}

type signerPrimitiveImpl struct {
	privateKey *ecdsa.PrivateKey
}

func (s signerPrimitiveImpl) SignTypedData(ctx context.Context, typedData apitypes.TypedData) (*SignatureResult, error) {
	// Create EIP-712 hash
	domainSeparator, err := typedData.HashStruct("EIP712Domain", typedData.Domain.Map())
	if err != nil {
		return nil, fmt.Errorf("failed to hash domain: %w", err)
	}

	// Use lenient hashing to allow extra fields in message (Python compatibility)
	typedDataHash, err := hashStructLenient(typedData, typedData.PrimaryType, typedData.Message)
	if err != nil {
		return nil, fmt.Errorf("failed to hash typed data: %w", err)
	}

	rawData := []byte{0x19, 0x01}
	rawData = append(rawData, domainSeparator...)
	rawData = append(rawData, typedDataHash...)
	msgHash := crypto.Keccak256Hash(rawData)

	signature, err := crypto.Sign(msgHash.Bytes(), s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign message: %w", err)
	}

	// Extract r, s, v components
	return &SignatureResult{
		R: hexutil.EncodeBig(new(big.Int).SetBytes(signature[:32])),
		S: hexutil.EncodeBig(new(big.Int).SetBytes(signature[32:64])),
		V: int(signature[64]) + 27,
	}, nil
}

func NewSignerPrimitive(privateKey *ecdsa.PrivateKey) Signer {
	return &signerPrimitiveImpl{
		privateKey: privateKey,
	}
}

type signerImpl struct {
	address string
	signer  signer.Interface
}

func (s *signerImpl) SignTypedData(ctx context.Context, typedData apitypes.TypedData) (*SignatureResult, error) {
	ret, err := s.signer.SignTypedData(
		ctx,
		uuid.NewString(),
		s.address,
		typedData,
	)
	if err != nil {
		return nil, err
	}
	return &SignatureResult{
		R: hexutil.EncodeBig(ret.R),
		S: hexutil.EncodeBig(ret.S),
		V: ret.V,
	}, nil
}

type signerMasterImpl struct {
	signer signer.Interface
}

func (m signerMasterImpl) CreateSigner(_ context.Context, address string) Signer {
	if !common.IsHexAddress(address) {
		return nil
	}
	return &signerImpl{
		address: address,
		signer:  m.signer,
	}
}

func NewSignerMaster(signer signer.Interface) SignerMaster {
	return &signerMasterImpl{
		signer: signer,
	}
}
