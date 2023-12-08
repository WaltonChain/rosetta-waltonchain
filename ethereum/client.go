// Copyright 2020 Coinbase, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ethereum

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"time"

	RosettaTypes "github.com/coinbase/rosetta-sdk-go/types"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	EthTypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"
	"golang.org/x/sync/semaphore"
)

const (
	gethHTTPTimeout = 120 * time.Second

	maxTraceConcurrency  = int64(16) // nolint:gomnd
	semaphoreTraceWeight = int64(1)  // nolint:gomnd

	// eip1559TxType is the EthTypes.Transaction.Type() value that indicates this transaction
	// follows EIP-1559.
	eip1559TxType = 2
)

type Receipt struct {
	BlockHash        common.Hash    `json:"blockHash"`
	BlockNumber      uint64         `json:"blockNumber"`
	TransactionIndex uint64         `json:"transactionIndex"`
	From             common.Address `json:"from"`
	To               common.Address `json:"to"`

	// Consensus fields
	PostState         []byte       `json:"root"`
	Status            uint         `json:"status"`
	CumulativeGasUsed *big.Int     `json:"cumulativeGasUsed"`
	Bloom             types.Bloom  `json:"logsBloom"`
	Logs              []*types.Log `json:"logs"`

	// Implementation fields (don't reorder!)
	TxHash          common.Hash    `json:"transactionHash"`
	ContractAddress common.Address `json:"contractAddress"`
	GasUsed         *big.Int       `json:"gasUsed"`
}

func (r *Receipt) MarshalJSON() ([]byte, error) {
	type Receipt struct {
		BlockHash        common.Hash    `json:"blockHash"`
		BlockNumber      hexutil.Uint64 `json:"blockNumber"`
		TransactionIndex hexutil.Uint64 `json:"transactionIndex"`
		From             common.Address `json:"from"`
		To               common.Address `json:"to"`

		PostState         hexutil.Bytes  `json:"root"`
		Status            hexutil.Uint   `json:"status"`
		CumulativeGasUsed *hexutil.Big   `json:"cumulativeGasUsed" gencodec:"required"`
		Bloom             types.Bloom    `json:"logsBloom"         gencodec:"required"`
		Logs              []*types.Log   `json:"logs"              gencodec:"required"`
		TxHash            common.Hash    `json:"transactionHash" gencodec:"required"`
		ContractAddress   common.Address `json:"contractAddress"`
		GasUsed           *hexutil.Big   `json:"gasUsed" gencodec:"required"`
	}
	var enc Receipt
	enc.BlockHash = r.BlockHash
	enc.BlockNumber = hexutil.Uint64(r.BlockNumber)
	enc.TransactionIndex = hexutil.Uint64(r.TransactionIndex)
	enc.From = r.From
	enc.To = r.To

	enc.PostState = r.PostState
	enc.Status = hexutil.Uint(r.Status)
	enc.CumulativeGasUsed = (*hexutil.Big)(r.CumulativeGasUsed)
	enc.Bloom = r.Bloom
	enc.Logs = r.Logs
	enc.TxHash = r.TxHash
	enc.ContractAddress = r.ContractAddress
	enc.GasUsed = (*hexutil.Big)(r.GasUsed)
	return json.Marshal(&enc)
}

func (r *Receipt) UnmarshalJSON(input []byte) error {
	type Receipt struct {
		BlockHash        *common.Hash    `json:"blockHash"`
		BlockNumber      *hexutil.Uint64 `json:"blockNumber"`
		TransactionIndex *hexutil.Uint64 `json:"transactionIndex"`
		From             *common.Address `json:"from"`
		To               *common.Address `json:"to"`

		PostState         hexutil.Bytes   `json:"root"`
		Status            *hexutil.Uint   `json:"status"`
		CumulativeGasUsed *hexutil.Big    `json:"cumulativeGasUsed" gencodec:"required"`
		Bloom             *types.Bloom    `json:"logsBloom"         gencodec:"required"`
		Logs              []*types.Log    `json:"logs"              gencodec:"required"`
		TxHash            *common.Hash    `json:"transactionHash" gencodec:"required"`
		ContractAddress   *common.Address `json:"contractAddress"`
		GasUsed           *hexutil.Big    `json:"gasUsed" gencodec:"required"`
	}
	var dec Receipt
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}
	if dec.BlockHash != nil {
		r.BlockHash = *dec.BlockHash
	}
	if dec.BlockNumber != nil {
		r.BlockNumber = uint64(*dec.BlockNumber)
	}
	if dec.TransactionIndex != nil {
		r.TransactionIndex = uint64(*dec.TransactionIndex)
	}
	if dec.From != nil {
		r.From = *dec.From
	}
	if dec.To != nil {
		r.To = *dec.To
	}

	if dec.PostState != nil {
		r.PostState = dec.PostState
	}
	if dec.Status != nil {
		r.Status = uint(*dec.Status)
	}
	if dec.CumulativeGasUsed == nil {
		return errors.New("missing required field 'cumulativeGasUsed' for Receipt")
	}
	r.CumulativeGasUsed = (*big.Int)(dec.CumulativeGasUsed)
	if dec.Bloom == nil {
		return errors.New("missing required field 'logsBloom' for Receipt")
	}
	r.Bloom = *dec.Bloom
	if dec.Logs == nil {
		return errors.New("missing required field 'logs' for Receipt")
	}
	r.Logs = dec.Logs
	if dec.TxHash == nil {
		return errors.New("missing required field 'transactionHash' for Receipt")
	}
	r.TxHash = *dec.TxHash
	if dec.ContractAddress != nil {
		r.ContractAddress = *dec.ContractAddress
	}
	if dec.GasUsed == nil {
		return errors.New("missing required field 'gasUsed' for Receipt")
	}
	r.GasUsed = (*big.Int)(dec.GasUsed)
	return nil
}

// LogConfig are the configuration options for structured logger the EVM
type LogConfig struct {
	DisableMemory  bool // disable memory capture
	DisableStack   bool // disable stack capture
	DisableStorage bool // disable storage capture
	FullStorage    bool // show full storage (slow)
	Limit          int  // maximum length of output, but zero means unlimited
}

// TraceArgs holds extra parameters to trace functions
type TraceArgs struct {
	*LogConfig
	Tracer  *string
	Timeout *string
}

// Client allows for querying a set of specific Ethereum endpoints in an
// idempotent manner. Client relies on the eth_*, debug_*, admin_*, and txpool_*
// methods and on the graphql endpoint.
//
// Client borrows HEAVILY from https://github.com/ethereum/go-ethereum/tree/master/ethclient.
type Client struct {
	p  *params.ChainConfig
	tc *TraceArgs

	c JSONRPC
	g GraphQL

	traceSemaphore *semaphore.Weighted

	skipAdminCalls bool
}

// NewClient creates a Client that from the provided url and params.
func NewClient(url string, params *params.ChainConfig, skipAdminCalls bool) (*Client, error) {
	c, err := rpc.DialHTTPWithClient(url, &http.Client{
		Timeout: gethHTTPTimeout,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: unable to dial node", err)
	}

	tc, err := loadTraceConfig()
	if err != nil {
		return nil, fmt.Errorf("%w: unable to load trace config", err)
	}

	g, err := newGraphQLClient(url)
	if err != nil {
		return nil, fmt.Errorf("%w: unable to create GraphQL client", err)
	}

	return &Client{params, tc, c, g, semaphore.NewWeighted(maxTraceConcurrency), skipAdminCalls}, nil
}

// Close shuts down the RPC client connection.
func (ec *Client) Close() {
	ec.c.Close()
}

// Status returns geth status information
// for determining node healthiness.
func (ec *Client) Status(ctx context.Context) (
	*RosettaTypes.BlockIdentifier,
	int64,
	*RosettaTypes.SyncStatus,
	[]*RosettaTypes.Peer,
	error,
) {
	header, err := ec.blockHeaderByNumber(ctx, nil)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	progress, err := ec.syncProgress(ctx)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	var syncStatus *RosettaTypes.SyncStatus
	if progress != nil {
		currentIndex := int64(progress.CurrentBlock)
		targetIndex := int64(progress.HighestBlock)

		syncStatus = &RosettaTypes.SyncStatus{
			CurrentIndex: &currentIndex,
			TargetIndex:  &targetIndex,
		}
	}

	peers, err := ec.peers(ctx)
	if err != nil {
		return nil, -1, nil, nil, err
	}

	return &RosettaTypes.BlockIdentifier{
			Hash:  header.Hash().Hex(),
			Index: header.Number.Int64(),
		},
		convertTime(header.Time),
		syncStatus,
		peers,
		nil
}

// PendingNonceAt returns the account nonce of the given account in the pending state.
// This is the nonce that should be used for the next transaction.
func (ec *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "eth_getTransactionCount", account, "pending")
	return uint64(result), err
}

// HeaderByHash returns the block header with the given hash.
func (ec *Client) HeaderByHash(ctx context.Context, hash common.Hash) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "eth_getBlockByHash", hash, false)
	if err == nil && head == nil {
		err = ethereum.NotFound
	}
	return head, err
}

// NonceAt returns the account nonce of the given account.
// The block number can be nil, in which case the nonce is taken from the latest known block.
func (ec *Client) NonceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (uint64, error) {
	var result hexutil.Uint64
	err := ec.c.CallContext(ctx, &result, "eth_getTransactionCount", account, toBlockNumArg(blockNumber))
	return uint64(result), err
}

// BalanceAt returns the wei balance of the given account.
// The block number can be nil, in which case the balance is taken from the latest known block.
func (ec *Client) BalanceAt(ctx context.Context, account common.Address, blockNumber *big.Int) (*big.Int, error) {
	var result hexutil.Big
	err := ec.c.CallContext(ctx, &result, "eth_getBalance", account, toBlockNumArg(blockNumber))
	return (*big.Int)(&result), err
}

// CodeAt returns the contract code of the given account.
// The block number can be nil, in which case the code is taken from the latest known block.
func (ec *Client) CodeAt(ctx context.Context, account common.Address, blockNumber *big.Int) ([]byte, error) {
	var result hexutil.Bytes
	err := ec.c.CallContext(ctx, &result, "eth_getCode", account, toBlockNumArg(blockNumber))
	return result, err
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (ec *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	var hex hexutil.Big
	if err := ec.c.CallContext(ctx, &hex, "eth_gasPrice"); err != nil {
		return nil, err
	}
	return (*big.Int)(&hex), nil
}

// Peers retrieves all peers of the node.
func (ec *Client) peers(ctx context.Context) ([]*RosettaTypes.Peer, error) {
	var info []*p2p.PeerInfo

	if ec.skipAdminCalls {
		return []*RosettaTypes.Peer{}, nil
	}

	if err := ec.c.CallContext(ctx, &info, "admin_peers"); err != nil {
		return nil, err
	}

	peers := make([]*RosettaTypes.Peer, len(info))
	for i, peerInfo := range info {
		peers[i] = &RosettaTypes.Peer{
			PeerID: peerInfo.ID,
			Metadata: map[string]interface{}{
				"name":      peerInfo.Name,
				"enode":     peerInfo.Enode,
				"caps":      peerInfo.Caps,
				"enr":       peerInfo.ENR,
				"protocols": peerInfo.Protocols,
			},
		}
	}

	return peers, nil
}

// SendTransaction injects a signed transaction into the pending pool for execution.
//
// If the transaction was a contract creation use the TransactionReceipt method to get the
// contract address after the transaction has been mined.
func (ec *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	data, err := rlp.EncodeToBytes(tx)
	if err != nil {
		return err
	}
	return ec.c.CallContext(ctx, nil, "eth_sendRawTransaction", hexutil.Encode(data))
}

func toBlockNumArg(number *big.Int) string {
	if number == nil {
		return "latest"
	}
	pending := big.NewInt(-1)
	if number.Cmp(pending) == 0 {
		return "pending"
	}
	return hexutil.EncodeBig(number)
}

// Transaction returns the transaction response of the Transaction identified
// by *RosettaTypes.TransactionIdentifier hash
func (ec *Client) Transaction(
	ctx context.Context,
	blockIdentifier *RosettaTypes.BlockIdentifier,
	transactionIdentifier *RosettaTypes.TransactionIdentifier,
) (*RosettaTypes.Transaction, error) {
	if transactionIdentifier.Hash == "" {
		return nil, errors.New("transaction hash is required")
	}

	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, "eth_getTransactionByHash", transactionIdentifier.Hash)
	if err != nil {
		return nil, fmt.Errorf("%w: transaction fetch failed", err)
	} else if len(raw) == 0 {
		return nil, ethereum.NotFound
	}

	// Decode transaction
	var body rpcTransaction

	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, err
	}

	var header *types.Header
	if blockIdentifier.Hash != "" {
		header, err = ec.blockHeaderByHash(ctx, blockIdentifier.Hash)
	} else {
		header, err = ec.blockHeaderByNumber(ctx, big.NewInt(blockIdentifier.Index))
	}

	if err != nil {
		return nil, fmt.Errorf("%w: could not get block header for %x", err, blockIdentifier.Hash)
	}

	receipt, err := ec.transactionReceipt(ctx, body.tx.Hash())
	if receipt.BlockHash != *body.BlockHash {
		return nil, fmt.Errorf(
			"%w: expected block hash %s for transaction but got %s",
			ErrBlockOrphaned,
			body.BlockHash.Hex(),
			receipt.BlockHash.Hex(),
		)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: could not get receipt for %x", err, body.tx.Hash())
	}

	var traces *Call
	var rawTraces json.RawMessage
	var addTraces bool
	//if header.Number.Int64() != GenesisBlockIndex { // not possible to get traces at genesis
	//	addTraces = true
	//	traces, rawTraces, err = ec.getTransactionTraces(ctx, body.tx.Hash())
	//	if err != nil {
	//		return nil, fmt.Errorf("%w: could not get traces for %x", err, body.tx.Hash())
	//	}
	//}

	loadedTx := body.LoadedTransaction()
	loadedTx.Transaction = body.tx
	feeAmount, feeBurned, err := calculateGas(body.tx, receipt, *header)
	if err != nil {
		return nil, err
	}
	loadedTx.FeeAmount = feeAmount
	loadedTx.FeeBurned = feeBurned
	loadedTx.Miner = MustChecksum(header.Coinbase.Hex())
	loadedTx.Receipt = receipt

	if addTraces {
		loadedTx.Trace = traces
		loadedTx.RawTrace = rawTraces
	}

	tx, err := ec.populateTransaction(loadedTx)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot parse %s", err, loadedTx.Transaction.Hash().Hex())
	}
	return tx, nil
}

// Block returns a populated block at the *RosettaTypes.PartialBlockIdentifier.
// If neither the hash or index is populated in the *RosettaTypes.PartialBlockIdentifier,
// the current block is returned.
func (ec *Client) Block(
	ctx context.Context,
	blockIdentifier *RosettaTypes.PartialBlockIdentifier,
) (*RosettaTypes.Block, error) {
	if blockIdentifier != nil {
		if blockIdentifier.Hash != nil {
			return ec.getParsedBlock(ctx, "eth_getBlockByHash", *blockIdentifier.Hash, true)
		}

		if blockIdentifier.Index != nil {
			return ec.getParsedBlock(
				ctx,
				"eth_getBlockByNumber",
				toBlockNumArg(big.NewInt(*blockIdentifier.Index)),
				true,
			)
		}
	}

	return ec.getParsedBlock(ctx, "eth_getBlockByNumber", toBlockNumArg(nil), true)
}

// Header returns a block header from the current canonical chain. If number is
// nil, the latest known header is returned.
func (ec *Client) blockHeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	var head *types.Header
	err := ec.c.CallContext(ctx, &head, "eth_getBlockByNumber", toBlockNumArg(number), false)
	if err == nil && head == nil {
		return nil, ethereum.NotFound
	}

	return head, err
}

// Header returns a block header from the current canonical chain. If hash is empty
// it returns error.
func (ec *Client) blockHeaderByHash(ctx context.Context, hash string) (*types.Header, error) {
	var head *types.Header
	if hash == "" {
		return nil, errors.New("hash is empty")
	}
	err := ec.c.CallContext(ctx, &head, "eth_getBlockByHash", hash, false)
	if err == nil && head == nil {
		return nil, ethereum.NotFound
	}

	return head, err
}

type rpcBlock struct {
	Hash         common.Hash      `json:"hash"`
	Transactions []rpcTransaction `json:"transactions"`
	UncleHashes  []common.Hash    `json:"uncles"`
}

func (ec *Client) getUncles(
	ctx context.Context,
	head *types.Header,
	body *rpcBlock,
) ([]*types.Header, error) {
	// Quick-verify transaction and uncle lists. This mostly helps with debugging the server.
	if head.UncleHash == types.EmptyUncleHash && len(body.UncleHashes) > 0 {
		return nil, fmt.Errorf(
			"server returned non-empty uncle list but block header indicates no uncles",
		)
	}
	if head.UncleHash != types.EmptyUncleHash && len(body.UncleHashes) == 0 {
		return nil, fmt.Errorf(
			"server returned empty uncle list but block header indicates uncles",
		)
	}
	if head.TxHash == types.EmptyRootHash && len(body.Transactions) > 0 {
		return nil, fmt.Errorf(
			"server returned non-empty transaction list but block header indicates no transactions",
		)
	}
	if head.TxHash != types.EmptyRootHash && len(body.Transactions) == 0 {
		return nil, fmt.Errorf(
			"server returned empty transaction list but block header indicates transactions",
		)
	}
	// Load uncles because they are not included in the block response.
	var uncles []*types.Header
	if len(body.UncleHashes) > 0 {
		uncles = make([]*types.Header, len(body.UncleHashes))
		reqs := make([]rpc.BatchElem, len(body.UncleHashes))
		for i := range reqs {
			reqs[i] = rpc.BatchElem{
				Method: "eth_getUncleByBlockHashAndIndex",
				Args:   []interface{}{body.Hash, hexutil.EncodeUint64(uint64(i))},
				Result: &uncles[i],
			}
		}
		if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
			return nil, err
		}
		for i := range reqs {
			if reqs[i].Error != nil {
				return nil, reqs[i].Error
			}
			if uncles[i] == nil {
				return nil, fmt.Errorf(
					"got null header for uncle %d of block %x",
					i,
					body.Hash[:],
				)
			}
		}
	}

	return uncles, nil
}

func (ec *Client) getBlock(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (
	*common.Hash,
	*types.Block,
	[]*loadedTransaction,
	error,
) {
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, blockMethod, args...)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: block fetch failed", err)
	} else if len(raw) == 0 {
		return nil, nil, nil, ethereum.NotFound
	}

	// Decode header and transactions
	var head types.Header
	var body rpcBlock
	if err := json.Unmarshal(raw, &head); err != nil {
		return nil, nil, nil, err
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return nil, nil, nil, err
	}

	uncles, err := ec.getUncles(ctx, &head, &body)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: unable to get uncles", err)
	}

	// Get all transaction receipts
	receipts, err := ec.getBlockReceipts(ctx, body.Hash, body.Transactions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: could not get receipts for %x", err, body.Hash[:])
	}

	// Get block traces (not possible to make idempotent block transaction trace requests)
	//
	// We fetch traces last because we want to avoid limiting the number of other
	// block-related data fetches we perform concurrently (we limit the number of
	// concurrent traces that are computed to 16 to avoid overwhelming geth).
	var traces []*rpcCall
	var rawTraces []*rpcRawCall
	var addTraces bool
	//if head.Number.Int64() != GenesisBlockIndex { // not possible to get traces at genesis
	//	addTraces = true
	//	traces, rawTraces, err = ec.getBlockTraces(ctx, body.Hash)
	//	if err != nil {
	//		return nil, nil, fmt.Errorf("%w: could not get traces for %x", err, body.Hash[:])
	//	}
	//}

	// Convert all txs to loaded txs
	txs := make([]*types.Transaction, len(body.Transactions))
	loadedTxs := make([]*loadedTransaction, len(body.Transactions))
	for i, tx := range body.Transactions {
		txs[i] = tx.tx
		receipt := receipts[i]
		if err != nil {
			return nil, nil, nil, fmt.Errorf("%w: failure getting effective gas price", err)
		}
		loadedTxs[i] = tx.LoadedTransaction()
		loadedTxs[i].Transaction = txs[i]

		feeAmount, feeBurned, err := calculateGas(txs[i], receipt, head)
		if err != nil {
			return nil, nil, nil, err
		}
		loadedTxs[i].FeeAmount = feeAmount
		loadedTxs[i].FeeBurned = feeBurned
		loadedTxs[i].Miner = MustChecksum(head.Coinbase.Hex())
		loadedTxs[i].Receipt = receipt

		// Continue if calls does not exist (occurs at genesis)
		if !addTraces {
			continue
		}

		loadedTxs[i].Trace = traces[i].Result
		loadedTxs[i].RawTrace = rawTraces[i].Result
	}

	return &body.Hash, types.NewBlockWithHeader(&head).WithBody(txs, uncles), loadedTxs, nil
}

func calculateGas(
	tx *types.Transaction,
	txReceipt *Receipt,
	head types.Header,
) (
	*big.Int, *big.Int, error,
) {
	gasUsed := txReceipt.GasUsed
	gasPrice, err := effectiveGasPrice(tx)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: failure getting effective gas price", err)
	}
	feeAmount := new(big.Int).Mul(gasUsed, gasPrice)
	feeBurned := big.NewInt(0)

	return feeAmount, feeBurned, nil
}

// effectiveGasPrice returns the price of gas charged to this transaction to be included in the
// block.
func effectiveGasPrice(tx *EthTypes.Transaction) (*big.Int, error) {
	return tx.GasPrice(), nil
}

func (ec *Client) getTransactionTraces(
	ctx context.Context,
	transactionHash common.Hash,
) (*Call, json.RawMessage, error) {
	if err := ec.traceSemaphore.Acquire(ctx, semaphoreTraceWeight); err != nil {
		return nil, nil, err
	}
	defer ec.traceSemaphore.Release(semaphoreTraceWeight)

	var call *Call
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, "debug_traceTransaction", transactionHash, ec.tc)
	if err != nil {
		return nil, nil, err
	}

	// Decode *Call
	if err := json.Unmarshal(raw, &call); err != nil {
		return nil, nil, err
	}

	return call, raw, nil
}

func (ec *Client) getBlockTraces(
	ctx context.Context,
	blockHash common.Hash,
) ([]*rpcCall, []*rpcRawCall, error) {
	if err := ec.traceSemaphore.Acquire(ctx, semaphoreTraceWeight); err != nil {
		return nil, nil, err
	}
	defer ec.traceSemaphore.Release(semaphoreTraceWeight)

	var calls []*rpcCall
	var rawCalls []*rpcRawCall
	var raw json.RawMessage
	err := ec.c.CallContext(ctx, &raw, "debug_traceBlockByHash", blockHash, ec.tc)
	if err != nil {
		return nil, nil, err
	}

	// Decode []*rpcCall
	fmt.Println("debug_traceBlockByHash request", blockHash, ec.tc)
	fmt.Println("debug_traceBlockByHash response", string(raw))
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil, nil, err
	}

	// Decode []*rpcRawCall
	if err := json.Unmarshal(raw, &rawCalls); err != nil {
		return nil, nil, err
	}

	return calls, rawCalls, nil
}

func (ec *Client) getBlockReceipts(
	ctx context.Context,
	blockHash common.Hash,
	txs []rpcTransaction,
) ([]*Receipt, error) {
	receipts := make([]*Receipt, len(txs))
	if len(txs) == 0 {
		return receipts, nil
	}

	reqs := make([]rpc.BatchElem, len(txs))
	for i := range reqs {
		reqs[i] = rpc.BatchElem{
			Method: "eth_getTransactionReceipt",
			Args:   []interface{}{txs[i].tx.Hash().Hex()},
			Result: &receipts[i],
		}
	}
	if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
		return nil, err
	}
	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}
		if receipts[i] == nil {
			return nil, fmt.Errorf("got empty receipt for %x", txs[i].tx.Hash().Hex())
		}

		if receipts[i].BlockHash != blockHash {
			return nil, fmt.Errorf(
				"%w: expected block hash %s for transaction but got %s",
				ErrBlockOrphaned,
				blockHash.Hex(),
				receipts[i].BlockHash.Hex(),
			)
		}
	}

	return receipts, nil
}

type rpcCall struct {
	Result *Call `json:"result"`
}

type rpcRawCall struct {
	Result json.RawMessage `json:"result"`
}

// Call is an Ethereum debug trace.
type Call struct {
	Type         string         `json:"type"`
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Value        *big.Int       `json:"value"`
	GasUsed      *big.Int       `json:"gasUsed"`
	Revert       bool
	ErrorMessage string  `json:"error"`
	Calls        []*Call `json:"calls"`
}

type flatCall struct {
	Type         string         `json:"type"`
	From         common.Address `json:"from"`
	To           common.Address `json:"to"`
	Value        *big.Int       `json:"value"`
	GasUsed      *big.Int       `json:"gasUsed"`
	Revert       bool
	ErrorMessage string `json:"error"`
}

func (t *Call) flatten() *flatCall {
	return &flatCall{
		Type:         t.Type,
		From:         t.From,
		To:           t.To,
		Value:        t.Value,
		GasUsed:      t.GasUsed,
		Revert:       t.Revert,
		ErrorMessage: t.ErrorMessage,
	}
}

// UnmarshalJSON is a custom unmarshaler for Call.
func (t *Call) UnmarshalJSON(input []byte) error {
	type CustomTrace struct {
		Type         string         `json:"type"`
		From         common.Address `json:"from"`
		To           common.Address `json:"to"`
		Value        *hexutil.Big   `json:"value"`
		GasUsed      *hexutil.Big   `json:"gasUsed"`
		Revert       bool
		ErrorMessage string  `json:"error"`
		Calls        []*Call `json:"calls"`
	}
	var dec CustomTrace
	if err := json.Unmarshal(input, &dec); err != nil {
		return err
	}

	t.Type = dec.Type
	t.From = dec.From
	t.To = dec.To
	if dec.Value != nil {
		t.Value = (*big.Int)(dec.Value)
	} else {
		t.Value = new(big.Int)
	}
	if dec.GasUsed != nil {
		t.GasUsed = (*big.Int)(dec.GasUsed)
	} else {
		t.GasUsed = new(big.Int)
	}
	if dec.ErrorMessage != "" {
		// Any error surfaced by the decoder means that the transaction
		// has reverted.
		t.Revert = true
	}
	t.ErrorMessage = dec.ErrorMessage
	t.Calls = dec.Calls
	return nil
}

// flattenTraces recursively flattens all traces.
func flattenTraces(data *Call, flattened []*flatCall) []*flatCall {
	results := append(flattened, data.flatten())
	for _, child := range data.Calls {
		// Ensure all children of a reverted call
		// are also reverted!
		if data.Revert {
			child.Revert = true

			// Copy error message from parent
			// if child does not have one
			if len(child.ErrorMessage) == 0 {
				child.ErrorMessage = data.ErrorMessage
			}
		}

		children := flattenTraces(child, flattened)
		results = append(results, children...)
	}
	return results
}

// traceOps returns all *RosettaTypes.Operation for a given
// array of flattened traces.
func traceOps(calls []*flatCall, startIndex int) []*RosettaTypes.Operation { // nolint: gocognit
	var ops []*RosettaTypes.Operation
	if len(calls) == 0 {
		return ops
	}

	destroyedAccounts := map[string]*big.Int{}
	for _, trace := range calls {
		// Handle partial transaction success
		metadata := map[string]interface{}{}
		opStatus := SuccessStatus
		if trace.Revert {
			opStatus = FailureStatus
			metadata["error"] = trace.ErrorMessage
		}

		var zeroValue bool
		if trace.Value.Sign() == 0 {
			zeroValue = true
		}

		// Skip all 0 value CallType operations (TODO: make optional to include)
		//
		// We can't continue here because we may need to adjust our destroyed
		// accounts map if a CallTYpe operation resurrects an account.
		shouldAdd := true
		if zeroValue && CallType(trace.Type) {
			shouldAdd = false
		}

		// Checksum addresses
		from := MustChecksum(trace.From.String())
		to := MustChecksum(trace.To.String())

		if shouldAdd {
			fromOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: int64(len(ops) + startIndex),
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: from,
				},
				Amount: &RosettaTypes.Amount{
					Value:    new(big.Int).Neg(trace.Value).String(),
					Currency: Currency,
				},
				Metadata: metadata,
			}
			if zeroValue {
				fromOp.Amount = nil
			} else {
				_, destroyed := destroyedAccounts[from]
				if destroyed && opStatus == SuccessStatus {
					destroyedAccounts[from] = new(big.Int).Sub(destroyedAccounts[from], trace.Value)
				}
			}

			ops = append(ops, fromOp)
		}

		// Add to destroyed accounts if SELFDESTRUCT
		// and overwrite existing balance.
		if trace.Type == SelfDestructOpType {
			destroyedAccounts[from] = new(big.Int)

			// If destination of of SELFDESTRUCT is self,
			// we should skip. In the EVM, the balance is reset
			// after the balance is increased on the destination
			// so this is a no-op.
			if from == to {
				continue
			}
		}

		// Skip empty to addresses (this may not
		// actually occur but leaving it as a
		// sanity check)
		if len(trace.To.String()) == 0 {
			continue
		}

		// If the account is resurrected, we remove it from
		// the destroyed accounts map.
		if CreateType(trace.Type) {
			delete(destroyedAccounts, to)
		}

		if shouldAdd {
			lastOpIndex := ops[len(ops)-1].OperationIdentifier.Index
			toOp := &RosettaTypes.Operation{
				OperationIdentifier: &RosettaTypes.OperationIdentifier{
					Index: lastOpIndex + 1,
				},
				RelatedOperations: []*RosettaTypes.OperationIdentifier{
					{
						Index: lastOpIndex,
					},
				},
				Type:   trace.Type,
				Status: RosettaTypes.String(opStatus),
				Account: &RosettaTypes.AccountIdentifier{
					Address: to,
				},
				Amount: &RosettaTypes.Amount{
					Value:    trace.Value.String(),
					Currency: Currency,
				},
				Metadata: metadata,
			}
			if zeroValue {
				toOp.Amount = nil
			} else {
				_, destroyed := destroyedAccounts[to]
				if destroyed && opStatus == SuccessStatus {
					destroyedAccounts[to] = new(big.Int).Add(destroyedAccounts[to], trace.Value)
				}
			}

			ops = append(ops, toOp)
		}
	}

	// Zero-out all destroyed accounts that are removed
	// during transaction finalization.
	for acct, val := range destroyedAccounts {
		if val.Sign() == 0 {
			continue
		}

		if val.Sign() < 0 {
			log.Fatalf("negative balance for suicided account %s: %s\n", acct, val.String())
		}

		ops = append(ops, &RosettaTypes.Operation{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: ops[len(ops)-1].OperationIdentifier.Index + 1,
			},
			Type:   DestructOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: acct,
			},
			Amount: &RosettaTypes.Amount{
				Value:    new(big.Int).Neg(val).String(),
				Currency: Currency,
			},
		})
	}

	return ops
}

type txExtraInfo struct {
	BlockNumber *string         `json:"blockNumber,omitempty"`
	BlockHash   *common.Hash    `json:"blockHash,omitempty"`
	From        *common.Address `json:"from,omitempty"`
}

type rpcTransaction struct {
	tx *types.Transaction
	txExtraInfo
}

func (tx *rpcTransaction) UnmarshalJSON(msg []byte) error {
	if err := json.Unmarshal(msg, &tx.tx); err != nil {
		return err
	}
	return json.Unmarshal(msg, &tx.txExtraInfo)
}

func (tx *rpcTransaction) LoadedTransaction() *loadedTransaction {
	ethTx := &loadedTransaction{
		Transaction: tx.tx,
		From:        tx.txExtraInfo.From,
		BlockNumber: tx.txExtraInfo.BlockNumber,
		BlockHash:   tx.txExtraInfo.BlockHash,
	}
	return ethTx
}

type loadedTransaction struct {
	Transaction *types.Transaction
	From        *common.Address
	BlockNumber *string
	BlockHash   *common.Hash
	FeeAmount   *big.Int
	FeeBurned   *big.Int // nil if no fees were burned
	Miner       string
	Status      bool

	Trace    *Call
	RawTrace json.RawMessage
	Receipt  *Receipt
}

func feeOps(tx *loadedTransaction) []*RosettaTypes.Operation {
	var minerEarnedAmount *big.Int
	if tx.FeeBurned == nil {
		minerEarnedAmount = tx.FeeAmount
	} else {
		minerEarnedAmount = new(big.Int).Sub(tx.FeeAmount, tx.FeeBurned)
	}
	ops := []*RosettaTypes.Operation{
		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 0,
			},
			Type:   FeeOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: MustChecksum(tx.From.String()),
			},
			Amount: &RosettaTypes.Amount{
				Value:    new(big.Int).Neg(minerEarnedAmount).String(),
				Currency: Currency,
			},
		},

		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: 1,
			},
			RelatedOperations: []*RosettaTypes.OperationIdentifier{
				{
					Index: 0,
				},
			},
			Type:   FeeOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: MustChecksum(tx.Miner),
			},
			Amount: &RosettaTypes.Amount{
				Value:    minerEarnedAmount.String(),
				Currency: Currency,
			},
		},
	}
	if tx.FeeBurned == nil || tx.FeeBurned.Sign()==0 {
		return ops
	}
	burntOp := &RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: 2, // nolint:gomnd
		},
		Type:   FeeOpType,
		Status: RosettaTypes.String(SuccessStatus),
		Account: &RosettaTypes.AccountIdentifier{
			Address: MustChecksum(tx.From.String()),
		},
		Amount: &RosettaTypes.Amount{
			Value:    new(big.Int).Neg(tx.FeeBurned).String(),
			Currency: Currency,
		},
	}
	return append(ops, burntOp)
}

func transactionOps(tx *loadedTransaction, ops []*RosettaTypes.Operation) []*RosettaTypes.Operation {
	index := int64(len(ops))

	transactionOps := []*RosettaTypes.Operation{
		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: index,
			},
			Type:   CallOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: MustChecksum(tx.From.String()),
			},
			Amount: &RosettaTypes.Amount{
				Value:    new(big.Int).Neg(tx.Transaction.Value()).String(),
				Currency: Currency,
			},
		},
		{
			OperationIdentifier: &RosettaTypes.OperationIdentifier{
				Index: index + 1,
			},
			RelatedOperations: []*RosettaTypes.OperationIdentifier{
				{
					Index: index,
				},
			},
			Type:   CallOpType,
			Status: RosettaTypes.String(SuccessStatus),
			Account: &RosettaTypes.AccountIdentifier{
				Address: MustChecksum(tx.Transaction.To().String()),
			},
			Amount: &RosettaTypes.Amount{
				Value:    tx.Transaction.Value().String(),
				Currency: Currency,
			},
		},
	}
	ops = append(ops, transactionOps...)
	return ops
}

// transactionReceipt returns the receipt of a transaction by transaction hash.
// Note that the receipt is not available for pending transactions.
func (ec *Client) transactionReceipt(
	ctx context.Context,
	txHash common.Hash,
) (*Receipt, error) {
	var r *Receipt
	err := ec.c.CallContext(ctx, &r, "eth_getTransactionReceipt", txHash)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}

	return r, err
}

func (ec *Client) blockByNumber(
	ctx context.Context,
	index *int64,
	showTxDetails bool,
) (map[string]interface{}, error) {
	var blockIndex string
	if index == nil {
		blockIndex = toBlockNumArg(nil)
	} else {
		blockIndex = toBlockNumArg(big.NewInt(*index))
	}

	r := make(map[string]interface{})
	err := ec.c.CallContext(ctx, &r, "eth_getBlockByNumber", blockIndex, showTxDetails)
	if err == nil {
		if r == nil {
			return nil, ethereum.NotFound
		}
	}

	return r, err
}

// contractCall returns the data specified by the given contract method
func (ec *Client) contractCall(
	ctx context.Context,
	params map[string]interface{},
) (map[string]interface{}, error) {
	// validate call input
	input, err := validateCallInput(params)
	if err != nil {
		return nil, err
	}

	// default query
	blockQuery := "latest"

	// if block number or hash, override blockQuery
	if input.BlockIndex > int64(0) {
		blockQuery = toBlockNumArg(big.NewInt(input.BlockIndex))
	} else if len(input.BlockHash) > 0 {
		blockQuery = input.BlockHash
	}

	// ensure valid contract address
	_, ok := ChecksumAddress(input.To)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// parameters for eth_call
	callParams := map[string]string{
		"to":   input.To,
		"data": input.Data,
	}

	var resp string
	if err := ec.c.CallContext(ctx, &resp, "eth_call", callParams, blockQuery); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data": resp,
	}, nil
}

// estimateGas returns the data specified by the given contract method
func (ec *Client) estimateGas(
	ctx context.Context,
	params map[string]interface{},
) (map[string]interface{}, error) {
	// validate call input
	input, err := validateCallInput(params)
	if err != nil {
		return nil, err
	}

	// ensure valid contract address
	_, ok := ChecksumAddress(input.To)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// ensure valid from address
	_, ok = ChecksumAddress(input.From)
	if !ok {
		return nil, ErrCallParametersInvalid
	}

	// parameters for eth_estimateGas
	estimateGasParams := map[string]string{
		"from": input.From,
		"to":   input.To,
		"data": input.Data,
	}

	var resp string
	if err := ec.c.CallContext(ctx, &resp, "eth_estimateGas", estimateGasParams); err != nil {
		return nil, err
	}

	return map[string]interface{}{
		"data": resp,
	}, nil
}

func validateCallInput(params map[string]interface{}) (*GetCallInput, error) {
	var input GetCallInput
	if err := RosettaTypes.UnmarshalMap(params, &input); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
	}

	// to address is required for call requests
	if len(input.To) == 0 {
		return nil, fmt.Errorf("%w:to address is missing from parameters", ErrCallParametersInvalid)
	}

	if len(input.Data) == 0 {
		return nil, fmt.Errorf("%w:data is missing from parameters", ErrCallParametersInvalid)
	}
	return &input, nil
}

func (ec *Client) getParsedBlock(
	ctx context.Context,
	blockMethod string,
	args ...interface{},
) (
	*RosettaTypes.Block,
	error,
) {
	hash, block, loadedTransactions, err := ec.getBlock(ctx, blockMethod, args...)
	if err != nil {
		return nil, fmt.Errorf("%w: could not get block", err)
	}

	blockIdentifier := &RosettaTypes.BlockIdentifier{
		Hash:  hash.String(),
		Index: block.Number().Int64(),
	}

	parentBlockIdentifier := blockIdentifier
	if blockIdentifier.Index != GenesisBlockIndex {
		parentBlockIdentifier = &RosettaTypes.BlockIdentifier{
			Hash:  block.ParentHash().Hex(),
			Index: blockIdentifier.Index - 1,
		}
	}
	minerBalance, err := ec.BalanceAt(ctx, common.HexToAddress(block.Coinbase().String()), block.Number())
	if err != nil {
		return nil, fmt.Errorf("%w: could not get BalanceAt", err)
	}

	txs, err := ec.populateTransactions(blockIdentifier, block, loadedTransactions, minerBalance)
	if err != nil {
		return nil, err
	}

	return &RosettaTypes.Block{
		BlockIdentifier:       blockIdentifier,
		ParentBlockIdentifier: parentBlockIdentifier,
		Timestamp:             convertTime(block.Time()),
		Transactions:          txs,
	}, nil
}

func convertTime(time uint64) int64 {
	return int64(time) * 1000
}

func (ec *Client) populateTransactions(
	blockIdentifier *RosettaTypes.BlockIdentifier,
	block *EthTypes.Block,
	loadedTransactions []*loadedTransaction,
	minerBalance *big.Int,
) ([]*RosettaTypes.Transaction, error) {
	transactions := make(
		[]*RosettaTypes.Transaction,
		len(block.Transactions())+1, // include reward tx
	)

	// Compute reward transaction (block + uncle reward)
	transactions[0] = ec.blockRewardTransaction(
		blockIdentifier,
		block.Coinbase().String(),
		block.Uncles(),
		minerBalance,
	)

	for i, tx := range loadedTransactions {
		transaction, err := ec.populateTransaction(
			tx,
		)
		if err != nil {
			return nil, fmt.Errorf("%w: cannot parse %s", err, tx.Transaction.Hash().Hex())
		}

		transactions[i+1] = transaction
	}

	return transactions, nil
}

func (ec *Client) populateTransaction(
	tx *loadedTransaction,
) (*RosettaTypes.Transaction, error) {
	var ops []*RosettaTypes.Operation

	// Compute fee operations
	feeOps := feeOps(tx)
	ops = append(ops, feeOps...)

	// Compute trace operations
	//traces := flattenTraces(tx.Trace, []*flatCall{})
	//
	//traceOps := traceOps(traces, len(ops))
	//ops = append(ops, traceOps...)

	ops = transactionOps(tx, ops)
	// Marshal receipt and trace data
	// TODO: replace with marshalJSONMap (used in `services`)
	receiptBytes, err := tx.Receipt.MarshalJSON()
	if err != nil {
		return nil, err
	}

	var receiptMap map[string]interface{}
	if err := json.Unmarshal(receiptBytes, &receiptMap); err != nil {
		return nil, err
	}

	var traceMap map[string]interface{}
	if tx.RawTrace!=nil{
		if err := json.Unmarshal(tx.RawTrace, &traceMap); err != nil {
			return nil, err
		}
	}

	populatedTransaction := &RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: tx.Transaction.Hash().Hex(),
		},
		Operations: ops,
		Metadata: map[string]interface{}{
			"gas_limit": hexutil.EncodeUint64(tx.Transaction.Gas()),
			"gas_price": hexutil.EncodeBig(tx.Transaction.GasPrice()),
			"receipt":   receiptMap,
			"trace":     traceMap,
		},
	}

	return populatedTransaction, nil
}

var (
	AddedRewardForMN = big.NewInt(5000)
	big5000          = new(big.Int).Mul(AddedRewardForMN, big.NewInt(1e+18))
)

func getReward(block, balance *big.Int) *big.Int {
	oneyear := big.NewInt(2 * 60 * 24 * 365)
	var reward *big.Int
	years := new(big.Int).Div(block, oneyear).Int64()

	if block.Int64() <= 40000 {
		reward = big.NewInt(1e+17)
	} else if block.Int64() > 40000 && block.Int64() <= 100000 {
		reward = big.NewInt(1e+18)
	} else if block.Int64() > 100000 && block.Int64() <= 200000 {
		reward = big.NewInt(2e+18)
	} else if years < 2 {
		reward = big.NewInt(25e+17)
		if balance.Cmp(big5000) >= 0 {
			reward = reward.Add(reward, big.NewInt(5e+17))
		}
	} else {
		var discount float64 = 100000
		y := years / 2
		for i := 0; int64(i) < y; i++ {
			discount = discount * 0.75
		}

		reward = big.NewInt(25e+17)
		if balance.Cmp(big5000) >= 0 {
			reward = reward.Add(reward, big.NewInt(5e+17))
		}

		reward = new(big.Int).Div(reward, big.NewInt(100000))
		reward = new(big.Int).Mul(reward, big.NewInt(int64(discount)))
	}

	return reward
}

// miningReward returns the mining reward
// for a given block height.
//
// Source:
// https://github.com/ethereum/go-ethereum/blob/master/consensus/ethash/consensus.go#L646-L653
func (ec *Client) miningReward(
	currentBlock *big.Int,
	minerBalance *big.Int,
) *big.Int {
	extraReward := getReward(currentBlock, big5000)
	noExtraReward := getReward(currentBlock, big5000)
	if minerBalance.Cmp(big.NewInt(0).Add(extraReward, big5000)) >= 0 {
		return big.NewInt(0).Set(extraReward)
	}

	return big.NewInt(0).Set(noExtraReward)
}

func (ec *Client) blockRewardTransaction(
	blockIdentifier *RosettaTypes.BlockIdentifier,
	miner string,
	uncles []*EthTypes.Header,
	minerBalance *big.Int,
) *RosettaTypes.Transaction {
	var ops []*RosettaTypes.Operation
	miningReward := ec.miningReward(big.NewInt(blockIdentifier.Index), minerBalance)

	// miner rewards
	minerReward := miningReward

	miningRewardOp := &RosettaTypes.Operation{
		OperationIdentifier: &RosettaTypes.OperationIdentifier{
			Index: 0,
		},
		Type:   MinerRewardOpType,
		Status: RosettaTypes.String(SuccessStatus),
		Account: &RosettaTypes.AccountIdentifier{
			Address: MustChecksum(miner),
		},
		Amount: &RosettaTypes.Amount{
			Value:    minerReward.Text(10),
			Currency: Currency,
		},
	}
	ops = append(ops, miningRewardOp)

	// no uncle rewards

	return &RosettaTypes.Transaction{
		TransactionIdentifier: &RosettaTypes.TransactionIdentifier{
			Hash: blockIdentifier.Hash,
		},
		Operations: ops,
	}
}

type rpcProgress struct {
	StartingBlock hexutil.Uint64
	CurrentBlock  hexutil.Uint64
	HighestBlock  hexutil.Uint64
	PulledStates  hexutil.Uint64
	KnownStates   hexutil.Uint64
}

// syncProgress retrieves the current progress of the sync algorithm. If there's
// no sync currently running, it returns nil.
func (ec *Client) syncProgress(ctx context.Context) (*ethereum.SyncProgress, error) {
	var raw json.RawMessage
	if err := ec.c.CallContext(ctx, &raw, "eth_syncing"); err != nil {
		return nil, err
	}

	var syncing bool
	if err := json.Unmarshal(raw, &syncing); err == nil {
		return nil, nil // Not syncing (always false)
	}

	var progress rpcProgress
	if err := json.Unmarshal(raw, &progress); err != nil {
		return nil, err
	}

	return &ethereum.SyncProgress{
		StartingBlock: uint64(progress.StartingBlock),
		CurrentBlock:  uint64(progress.CurrentBlock),
		HighestBlock:  uint64(progress.HighestBlock),
		PulledStates:  uint64(progress.PulledStates),
		KnownStates:   uint64(progress.KnownStates),
	}, nil
}

func (ec *Client) blockHeader(
	ctx context.Context,
	blockIdentifier *RosettaTypes.PartialBlockIdentifier,
) (*EthTypes.Header, error) {
	var (
		header *EthTypes.Header
		err    error
	)

	if blockIdentifier == nil || (blockIdentifier.Hash == nil && blockIdentifier.Index == nil) {
		err = ec.c.CallContext(ctx, &header, "eth_getBlockByNumber", toBlockNumArg(nil), false)
	} else {
		if blockIdentifier.Index != nil {
			err = ec.c.CallContext(ctx, &header, "eth_getBlockByNumber", toBlockNumArg(big.NewInt(*blockIdentifier.Index)), false)
		} else {
			err = ec.c.CallContext(ctx, &header, "eth_getBlockByHash", common.HexToHash(*blockIdentifier.Hash), false)
		}
	}

	if err == nil && header == nil {
		return nil, ethereum.NotFound
	}
	return header, err
}

// Balance returns the balance of a *RosettaTypes.AccountIdentifier
// at a *RosettaTypes.PartialBlockIdentifier.
//
// We must use graphql to get the balance atomically (the
// rpc method for balance does not allow for querying
// by block hash nor return the block hash where
// the balance was fetched).

func (ec *Client) Balance(
	ctx context.Context,
	account *RosettaTypes.AccountIdentifier,
	blockIdentifier *RosettaTypes.PartialBlockIdentifier,
) (*RosettaTypes.AccountBalanceResponse, error) {
	header, err := ec.blockHeader(ctx, blockIdentifier)
	if err != nil {
		return nil, fmt.Errorf("failed to get block header: %w", err)
	}

	var (
		nativeBalance hexutil.Big
		nonce         hexutil.Uint64
	)

	// Get ETH balance, nonce, and bytecode of smart contract
	blockNum := hexutil.EncodeUint64(header.Number.Uint64())
	reqs := []rpc.BatchElem{
		{
			Method: "eth_getBalance",
			Args:   []interface{}{account.Address, blockNum},
			Result: &nativeBalance,
		},
		{
			Method: "eth_getTransactionCount",
			Args:   []interface{}{account.Address, blockNum},
			Result: &nonce,
		},
	}
	if err := ec.c.BatchCallContext(ctx, reqs); err != nil {
		return nil, err
	}
	for i := range reqs {
		if reqs[i].Error != nil {
			return nil, reqs[i].Error
		}
	}

	return &RosettaTypes.AccountBalanceResponse{
		Balances: []*RosettaTypes.Amount{
			{
				Value:    nativeBalance.String(),
				Currency: Currency,
			},
		},
		BlockIdentifier: &RosettaTypes.BlockIdentifier{
			Hash:  header.Hash().Hex(),
			Index: header.Number.Int64(),
		},
		Metadata: map[string]interface{}{
			"nonce": int64(nonce),
		},
	}, nil
}

// GetBlockByNumberInput is the input to the call
// method "eth_getBlockByNumber".
type GetBlockByNumberInput struct {
	Index         *int64 `json:"index,omitempty"`
	ShowTxDetails bool   `json:"show_transaction_details"`
}

// GetTransactionReceiptInput is the input to the call
// method "eth_getTransactionReceipt".
type GetTransactionReceiptInput struct {
	TxHash string `json:"tx_hash"`
}

// GetCallInput is the input to the call
// method "eth_call", "eth_estimateGas".
type GetCallInput struct {
	BlockIndex int64  `json:"index,omitempty"`
	BlockHash  string `json:"hash,omitempty"`
	From       string `json:"from"`
	To         string `json:"to"`
	Gas        int64  `json:"gas"`
	GasPrice   int64  `json:"gas_price"`
	Value      int64  `json:"value"`
	Data       string `json:"data"`
}

// Call handles calls to the /call endpoint.
func (ec *Client) Call(
	ctx context.Context,
	request *RosettaTypes.CallRequest,
) (*RosettaTypes.CallResponse, error) {
	switch request.Method { // nolint:gocritic
	case "eth_getBlockByNumber":
		var input GetBlockByNumberInput
		if err := RosettaTypes.UnmarshalMap(request.Parameters, &input); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
		}

		res, err := ec.blockByNumber(ctx, input.Index, input.ShowTxDetails)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: res,
		}, nil
	case "eth_getTransactionReceipt":
		var input GetTransactionReceiptInput
		if err := RosettaTypes.UnmarshalMap(request.Parameters, &input); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallParametersInvalid, err.Error())
		}

		if len(input.TxHash) == 0 {
			return nil, fmt.Errorf("%w:tx_hash missing from params", ErrCallParametersInvalid)
		}

		receipt, err := ec.transactionReceipt(ctx, common.HexToHash(input.TxHash))
		if err != nil {
			return nil, err
		}

		// We cannot use RosettaTypes.MarshalMap because geth uses a custom
		// marshaler to convert *types.Receipt to JSON.
		jsonOutput, err := receipt.MarshalJSON()
		if err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallOutputMarshal, err.Error())
		}

		var receiptMap map[string]interface{}
		if err := json.Unmarshal(jsonOutput, &receiptMap); err != nil {
			return nil, fmt.Errorf("%w: %s", ErrCallOutputMarshal, err.Error())
		}

		// We must encode data over the wire so we can unmarshal correctly
		return &RosettaTypes.CallResponse{
			Result: receiptMap,
		}, nil
	case "eth_call":
		resp, err := ec.contractCall(ctx, request.Parameters)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: resp,
		}, nil
	case "eth_estimateGas":
		resp, err := ec.estimateGas(ctx, request.Parameters)
		if err != nil {
			return nil, err
		}

		return &RosettaTypes.CallResponse{
			Result: resp,
		}, nil
	}

	return nil, fmt.Errorf("%w: %s", ErrCallMethodInvalid, request.Method)
}

// txPoolContentResponse represents the response for a call to
// geth node on the "txpool_content" method.
type txPoolContentResponse struct {
	Pending txPool `json:"pending"`
	Queued  txPool `json:"queued"`
}

type txPool map[string]txPoolInner

type txPoolInner map[string]rpcTransaction

// GetMempool get and returns all the transactions on Ethereum TxPool (pending and queued).
func (ec *Client) GetMempool(ctx context.Context) (*RosettaTypes.MempoolResponse, error) {
	var response txPoolContentResponse
	if err := ec.c.CallContext(ctx, &response, "txpool_content"); err != nil {
		return nil, err
	}

	identifiers := make([]*RosettaTypes.TransactionIdentifier, 0)

	for _, inner := range response.Pending {
		for _, info := range inner {
			identifiers = append(identifiers, &RosettaTypes.TransactionIdentifier{
				Hash: info.tx.Hash().String(),
			})
		}
	}

	for _, inner := range response.Queued {
		for _, info := range inner {
			identifiers = append(identifiers, &RosettaTypes.TransactionIdentifier{
				Hash: info.tx.Hash().String(),
			})
		}
	}

	return &RosettaTypes.MempoolResponse{TransactionIdentifiers: identifiers}, nil
}
