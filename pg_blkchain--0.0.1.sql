-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_blkchain" to load this file. \quit

-- uint32 is represented as an INT because both are 4 bytes. INT,
-- however, is signed, so a value above 4294967295 will be negative.

-- names are generally preserved from the core code but without the
-- type prefix, i.e. nVersion is version.

CREATE TYPE CBlock AS (version INT, hashPrevBlock BYTEA, hashMerkleRoot BYTEA, time INT, bits INT, nonce INT);
CREATE FUNCTION get_block(bytea) RETURNS CBlock
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE CTx AS (hash BYTEA, version INT, lockTime INT);
CREATE FUNCTION get_tx(tx bytea) RETURNS CTx
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE CTxIn AS (n INT, prevout_hash BYTEA, prevout_n INT, scriptSig BYTEA, sequence INT);
CREATE FUNCTION get_vin(tx bytea) RETURNS SETOF CTxIn
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE CTxOut AS (n INT, value BIGINT, scriptPubKey BYTEA);
CREATE FUNCTION get_vout(tx bytea) RETURNS SETOF CTxOut
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE CScriptOp AS (op_sym TEXT, op INT, data BYTEA);
CREATE FUNCTION parse_script(bytea) RETURNS SETOF CScriptOp
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION verify_sig(txTo bytea, txFrom bytea, int) RETURNS bool
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

-- experimental
CREATE FUNCTION get_vout_arr(tx bytea) RETURNS CTxOut[]
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION get_vin_arr(tx bytea) RETURNS CTxIn[]
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE TYPE COutPt AS (hash BYTEA, n INT);
CREATE FUNCTION get_vin_outpt_arr(tx bytea) RETURNS COutPt[]
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION get_vin_outpt_jsonb(tx bytea) RETURNS JSONB
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

CREATE FUNCTION get_vin_outpt_bytea(tx bytea) RETURNS BYTEA[]
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;

-- build_vin

CREATE FUNCTION build_vin_transfn(internal, prevout_hash BYTEA, prevout_n INT, scriptsig BYTEA, seq INT) RETURNS internal
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION build_vin_finalfn(internal) RETURNS BYTEA
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE AGGREGATE build_vin(prevout_hash BYTEA, prevout_n INT, scriptsig BYTEA, seq INT) (
  sfunc = build_vin_transfn,
  stype = internal,
  finalfunc = build_vin_finalfn
);

-- build_vout

CREATE FUNCTION build_vout_transfn(internal, value BIGINT, scriptpubkey BYTEA) RETURNS internal
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE PARALLEL SAFE;

CREATE FUNCTION build_vout_finalfn(internal) RETURNS BYTEA
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT PARALLEL SAFE;

CREATE AGGREGATE build_vout(value BIGINT, scriptpubkey BYTEA) (
  sfunc = build_vout_transfn,
  stype = internal,
  finalfunc = build_vout_finalfn
);

-- int4send_le

CREATE FUNCTION int4send_le(INT) RETURNS BYTEA
AS '$libdir/pg_blkchain'
LANGUAGE C IMMUTABLE STRICT;
