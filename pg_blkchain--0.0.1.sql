-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_blkchain" to load this file. \quit

CREATE FUNCTION verify_sig(bytea, bytea, int) RETURNS bool
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

-- CREATE FUNCTION eval_script(bytea, bytea, bytea, int) RETURNS bool
-- AS '$libdir/pg_blkchain'
-- LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE TxIn AS (n INT, prevout_hash BYTEA, prevout_n INT, scriptsig BYTEA, sequence BIGINT);
CREATE FUNCTION get_vin(bytea) RETURNS SETOF TxIn
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE TxOut AS (n INT, value BIGINT, scriptpubkey BYTEA);
CREATE FUNCTION get_vout(bytea) RETURNS SETOF TxOut
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE ScriptOp AS (op_sym TEXT, op INT, data BYTEA);
CREATE FUNCTION parse_script(bytea) RETURNS SETOF ScriptOp
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

-- experimental
CREATE FUNCTION get_vout_arr(bytea) RETURNS CTxOut[]
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;
