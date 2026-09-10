//===----------------------------------------------------------------------===//
// A transaction manager that manages nothing, deliberately.
//
// Analysis Services has no transaction this extension could join: it is read
// only here, every request is a self-contained SOAP round trip, and the server
// session carries no isolation this side could honour. Pretending otherwise —
// by, say, holding a connection open across a DuckDB transaction and calling it
// a unit of work — would claim a guarantee that does not exist.
//===----------------------------------------------------------------------===//
#pragma once

#include "duckdb.hpp"
#include "duckdb/transaction/transaction.hpp"
#include "duckdb/transaction/transaction_manager.hpp"

namespace duckdb {

class XmlaTransaction : public Transaction {
public:
	XmlaTransaction(TransactionManager &manager, ClientContext &context) : Transaction(manager, context) {}
};

class XmlaTransactionManager : public TransactionManager {
public:
	explicit XmlaTransactionManager(AttachedDatabase &db) : TransactionManager(db) {}

	Transaction &StartTransaction(ClientContext &context) override;
	ErrorData CommitTransaction(ClientContext &context, Transaction &transaction) override;
	void RollbackTransaction(Transaction &transaction) override;
	void Checkpoint(ClientContext &context, bool force = false) override;

private:
	mutex transaction_lock;
	reference_map_t<Transaction, unique_ptr<XmlaTransaction>> transactions;
};

}  // namespace duckdb
