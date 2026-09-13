INSERT INTO audit_chain_lock (id)
SELECT 1
WHERE NOT EXISTS (SELECT 1 FROM audit_chain_lock WHERE id = 1);
