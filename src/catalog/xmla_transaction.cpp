#include "catalog/xmla_transaction.hpp"

namespace duckdb {

Transaction &XmlaTransactionManager::StartTransaction(ClientContext &context) {
	auto transaction = make_uniq<XmlaTransaction>(*this, context);
	auto &result = *transaction;
	lock_guard<mutex> guard(transaction_lock);
	transactions[result] = std::move(transaction);
	return result;
}

ErrorData XmlaTransactionManager::CommitTransaction(ClientContext &, Transaction &transaction) {
	lock_guard<mutex> guard(transaction_lock);
	transactions.erase(transaction);
	return ErrorData();
}

void XmlaTransactionManager::RollbackTransaction(Transaction &transaction) {
	lock_guard<mutex> guard(transaction_lock);
	transactions.erase(transaction);
}

void XmlaTransactionManager::Checkpoint(ClientContext &, bool) {
	// Nothing to checkpoint: this catalog owns no storage. A no-op rather than an
	// error, because DuckDB checkpoints attached databases as a matter of course
	// and failing here would make ordinary operations fail for no reason.
}

}  // namespace duckdb
