#include "postgres.h"
#include "fmgr.h"
#include "utils/builtins.h"

#include "ccoin/script.h"
#include "ccoin/core.h"

/* For SRF */
#include "access/htup_details.h"
#include "funcapi.h"

/* pg array */
#include "utils/array.h"
#include "utils/lsyscache.h"

/* jsonb */
#include "utils/jsonb.h"
#include "utils/bytea.h"
#include "utils/numeric.h"

/* bytea arr */
#include "catalog/pg_type.h"

PG_MODULE_MAGIC;

PG_FUNCTION_INFO_V1(verify_sig);
Datum
verify_sig(PG_FUNCTION_ARGS)
{
    bytea *btxto      = PG_GETARG_BYTEA_P(0);
    bytea *btxfrom    = PG_GETARG_BYTEA_P(1);
    int32 n           = PG_GETARG_INT32(2);

    struct const_buffer txfrombuf = { VARDATA(btxfrom), VARSIZE(btxfrom)-VARHDRSZ };
    struct const_buffer txtobuf   = { VARDATA(btxto), VARSIZE(btxto)-VARHDRSZ };

    bool result;

    struct bp_tx txfrom;
    struct bp_tx txto;
    struct bp_utxo coin;

    bp_tx_init(&txfrom);
    if (!deser_bp_tx(&txfrom, &txfrombuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse txFrom transaction")));
    /* bp_tx_calc_sha256(&txfrom); */
    txfrom.sha256_valid = true; /* shortcut - why wouldn't it be? */

    bp_tx_init(&txto);
    if (!deser_bp_tx(&txto, &txtobuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse txTo transaction")));

    memset(&coin, 0, sizeof(coin));
    bp_utxo_init(&coin);

    if (!bp_utxo_from_tx(&coin, &txfrom,
                         false, /* is_coinbase */
                         0))    /* height - doesn't matter */
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("bp_utxo_from_tx() failed")));

    result = bp_verify_sig(&coin, &txto, n, SCRIPT_VERIFY_P2SH, SIGHASH_ALL); // ZZZ SIGHASH_ALL?

    bp_tx_free(&txfrom);
    bp_tx_free(&txto);
    bp_utxo_free(&coin);

    PG_RETURN_BOOL(result);
}

PG_FUNCTION_INFO_V1(get_vin);
Datum
get_vin(PG_FUNCTION_ARGS)
{
    typedef struct
    {
        TupleDesc	 tupdesc;
        struct bp_tx *tx;
    } tcontext;

    FuncCallContext   *funcctx;
    int               call_cntr;
    int               max_calls;
    TupleDesc         tupdesc;
    tcontext          *ctx;

    if (SRF_IS_FIRSTCALL())
    {
        MemoryContext oldcontext;
        bytea         *b_tx = PG_GETARG_BYTEA_P(0);
        struct const_buffer cbuf = { VARDATA(b_tx), VARSIZE(b_tx)-VARHDRSZ };
        struct bp_tx  *tx;

        funcctx = SRF_FIRSTCALL_INIT();
        oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("function called in context that cannot accept the return type")));

		ctx = (tcontext *) palloc(sizeof(tcontext));
		ctx->tupdesc = BlessTupleDesc(tupdesc);

        tx = (struct bp_tx *)palloc(sizeof(struct bp_tx));
        bp_tx_init(tx);

        if (!deser_bp_tx(tx, &cbuf))
            ereport(ERROR,
                    (errcode(ERRCODE_DATA_EXCEPTION),
                     errmsg("unable to parse transaction")));

        if (tx->vin->len > 0)
        {
            funcctx->max_calls = tx->vin->len;
            ctx->tx = tx;
            funcctx->user_fctx = (void *) ctx;
        }
        else
        {
			/* fast track when no results */
            bp_tx_free(tx);
            pfree(tx);
            pfree(ctx);
            MemoryContextSwitchTo(oldcontext);
            SRF_RETURN_DONE(funcctx);
        }

        MemoryContextSwitchTo(oldcontext);
    }

    funcctx = SRF_PERCALL_SETUP();
    call_cntr = funcctx->call_cntr;
    max_calls = funcctx->max_calls;
	ctx = funcctx->user_fctx;

    if (call_cntr < max_calls)
    {

        struct bp_tx *tx = ctx->tx;
        struct bp_txin *txin;

		Datum		values[5];
		bool		nulls[5] = {false}; /* init all values to false */
        HeapTuple   tuple;
        Datum       result;
        bytea       *poh;
        bytea       *sig;

        txin = parr_idx(tx->vin, call_cntr);

        /* n */
        values[0] = UInt32GetDatum(call_cntr);
        nulls[0] = false;

        /* prevout_hash */
        poh = (bytea *) palloc(sizeof(bu256_t) + VARHDRSZ);
        SET_VARSIZE(poh, sizeof(bu256_t) + VARHDRSZ);
        memcpy(VARDATA(poh), &txin->prevout.hash, sizeof(bu256_t));
        values[1] = PointerGetDatum(poh);

        /* prevout_n */
        values[2] = UInt32GetDatum(txin->prevout.n);

        /* scriptsig */
        sig = (bytea *) palloc(txin->scriptSig->len + VARHDRSZ);
        SET_VARSIZE(sig, txin->scriptSig->len + VARHDRSZ);
        memcpy(VARDATA(sig), txin->scriptSig->str, txin->scriptSig->len);
        values[3] = PointerGetDatum(sig);

        /* sequence */
        values[4] = UInt32GetDatum(txin->nSequence);

		/* Build CTxOut tuple */
		tuple = heap_form_tuple(ctx->tupdesc, values, nulls);
		result = HeapTupleGetDatum(tuple);

        SRF_RETURN_NEXT(funcctx, result);
    }
    else
    {
        /* clean up */
        bp_tx_free(ctx->tx);
        pfree(ctx->tx);
        pfree(ctx);

        SRF_RETURN_DONE(funcctx);
    }
}

PG_FUNCTION_INFO_V1(get_vout);
Datum
get_vout(PG_FUNCTION_ARGS)
{

    typedef struct
    {
        TupleDesc	 tupdesc;
        struct bp_tx *tx;
    } tcontext;

    FuncCallContext   *funcctx;
    int               call_cntr;
    int               max_calls;
    TupleDesc         tupdesc;
    tcontext *ctx;

    if (SRF_IS_FIRSTCALL())
    {
        MemoryContext oldcontext;
        bytea         *b_tx = PG_GETARG_BYTEA_P(0);
        struct const_buffer cbuf = { VARDATA(b_tx), VARSIZE(b_tx)-VARHDRSZ };
        struct bp_tx  *tx;

        funcctx = SRF_FIRSTCALL_INIT();
        oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("function called in context that cannot accept the return type")));

		ctx = (tcontext *) palloc(sizeof(tcontext));
		ctx->tupdesc = BlessTupleDesc(tupdesc);

        tx = (struct bp_tx *)palloc(sizeof(struct bp_tx));
        bp_tx_init(tx);

        if (!deser_bp_tx(tx, &cbuf))
            ereport(ERROR,
                    (errcode(ERRCODE_DATA_EXCEPTION),
                     errmsg("unable to parse transaction")));

        if (tx->vout->len > 0)
        {
            funcctx->max_calls = tx->vout->len;
            ctx->tx = tx;
            funcctx->user_fctx = (void *) ctx;
        }
        else
        {
			/* fast track when no results */
            bp_tx_free(tx);
            pfree(tx);
            pfree(ctx);
            MemoryContextSwitchTo(oldcontext);
            SRF_RETURN_DONE(funcctx);
        }

        MemoryContextSwitchTo(oldcontext);
    }

    funcctx = SRF_PERCALL_SETUP();
    call_cntr = funcctx->call_cntr;
    max_calls = funcctx->max_calls;
	ctx = funcctx->user_fctx;

    if (call_cntr < max_calls)
    {

        struct bp_tx *tx = ctx->tx;
        struct bp_txout *txout;

		Datum		values[3];
		bool		nulls[3] = {false};
        HeapTuple   tuple;
        Datum       result;
        bytea       *pk;

        txout = parr_idx(tx->vout, call_cntr);

        /* n */
        values[0] = UInt32GetDatum(call_cntr);

        /* value */
        values[1] = Int64GetDatum(txout->nValue);

        /* scriptpubkey */
        pk = (bytea *) palloc(txout->scriptPubKey->len + VARHDRSZ);
        SET_VARSIZE(pk, txout->scriptPubKey->len + VARHDRSZ);
        memcpy(VARDATA(pk), txout->scriptPubKey->str, txout->scriptPubKey->len);
        values[2] = PointerGetDatum(pk);

		/* Build CTxOut tuple */
		tuple = heap_form_tuple(ctx->tupdesc, values, nulls);
		result = HeapTupleGetDatum(tuple);

        SRF_RETURN_NEXT(funcctx, result);
    }
    else
    {
        /* clean up */
        bp_tx_free(ctx->tx);
        pfree(ctx->tx);
        pfree(ctx);

        SRF_RETURN_DONE(funcctx);
    }
}

PG_FUNCTION_INFO_V1(get_tx);
Datum
get_tx(PG_FUNCTION_ARGS)
{

    bytea         *b_tx = PG_GETARG_BYTEA_P(0);
    struct const_buffer cbuf = { VARDATA(b_tx), VARSIZE(b_tx)-VARHDRSZ };
    struct bp_tx  *tx;

    Datum		values[3];
    bool		nulls[3] = {false};
    TupleDesc   tupdesc;
    HeapTuple   tuple;
    Datum       result;

    bytea       *hash;

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function called in context that cannot accept the return type")));

    tx = (struct bp_tx *)palloc(sizeof(struct bp_tx));
    bp_tx_init(tx);

    if (!deser_bp_tx(tx, &cbuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse transaction")));

    bp_tx_calc_sha256(tx);

    /* hash */
    hash = (bytea *) palloc(32 + VARHDRSZ);
    SET_VARSIZE(hash, 32+VARHDRSZ);
    memcpy(VARDATA(hash), &tx->sha256, 32);
    values[0] = PointerGetDatum(hash);

    /* version */
    values[1] = UInt32GetDatum(tx->nVersion);

    /* locktime */
    values[2] = UInt32GetDatum(tx->nLockTime);

    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);

    bp_tx_free(tx);
    pfree(tx);

    PG_RETURN_DATUM(result);
}

PG_FUNCTION_INFO_V1(get_block);
Datum
get_block(PG_FUNCTION_ARGS)
{

    bytea         *b_blk = PG_GETARG_BYTEA_P(0);
    struct const_buffer cbuf = { VARDATA(b_blk), VARSIZE(b_blk)-VARHDRSZ };
    struct bp_block  *blk;

    Datum		values[6];
    bool		nulls[6] = {false};
    TupleDesc   tupdesc;
    HeapTuple   tuple;
    Datum       result;

    bytea       *hashPrev;
    bytea       *hashMerkle;

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function called in context that cannot accept the return type")));

    blk = (struct bp_block *)palloc(sizeof(struct bp_block));
    bp_block_init(blk);

    if (!deser_bp_block(blk, &cbuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse block header")));

    /* version */
    values[0] = UInt32GetDatum(blk->nVersion);

    /* hashPrevBlock */
    hashPrev = (bytea *) palloc(32 + VARHDRSZ);
    SET_VARSIZE(hashPrev, 32+VARHDRSZ);
    memcpy(VARDATA(hashPrev), &blk->hashPrevBlock, 32);
    values[1] = PointerGetDatum(hashPrev);

    /* hashMerkleRoot */
    hashMerkle = (bytea *) palloc(32 + VARHDRSZ);
    SET_VARSIZE(hashMerkle, 32+VARHDRSZ);
    memcpy(VARDATA(hashMerkle), &blk->hashMerkleRoot, 32);
    values[2] = PointerGetDatum(hashMerkle);

    /* time */
    values[3] = UInt32GetDatum(blk->nTime);

    /* bits */
    values[4] = UInt32GetDatum(blk->nBits);

    /* nonce */
    values[5] = UInt32GetDatum(blk->nNonce);

    tuple = heap_form_tuple(tupdesc, values, nulls);
    result = HeapTupleGetDatum(tuple);

    bp_block_free(blk);
    pfree(blk);

    PG_RETURN_DATUM(result);
}

PG_FUNCTION_INFO_V1(parse_script);
Datum
parse_script(PG_FUNCTION_ARGS)
{

    typedef struct
    {
        TupleDesc	          tupdesc;
        struct bscript_parser *bp;
    } tcontext;

    FuncCallContext   *funcctx;
    TupleDesc         tupdesc;
    tcontext          *ctx;
    struct bscript_op op;

    if (SRF_IS_FIRSTCALL())
    {
        MemoryContext oldcontext;
        bytea         *ba = PG_GETARG_BYTEA_P(0);
        struct const_buffer *buf;

        funcctx = SRF_FIRSTCALL_INIT();
        oldcontext = MemoryContextSwitchTo(funcctx->multi_call_memory_ctx);

        if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
            ereport(ERROR,
                    (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                     errmsg("function called in context that cannot accept the return type")));

		ctx = (tcontext *) palloc(sizeof(tcontext));
		ctx->tupdesc = BlessTupleDesc(tupdesc);
        ctx->bp = (struct bscript_parser *) palloc(sizeof(struct bscript_parser));
        buf = (struct const_buffer *) palloc(sizeof(struct const_buffer));
        buf->p = VARDATA(ba);
        buf->len = VARSIZE(ba)-VARHDRSZ;
        bsp_start(ctx->bp, buf);

        funcctx->user_fctx = (void *) ctx;

        MemoryContextSwitchTo(oldcontext);
    }

    /* each time set up */
    funcctx = SRF_PERCALL_SETUP();
	ctx = funcctx->user_fctx;

    if (bsp_getop(&op, ctx->bp))
    {
		Datum		values[3];
		bool		nulls[3] = {false}; /* init all values to false */
        HeapTuple   tuple;
        Datum       result;
        bytea       *data;
        text        *op_sym;
        const char  *ops;
        int         opsz;

        /* op_sym */
        if (op.op == 0x00)
            ops = "OP_FALSE";
        else if (op.op < 0x4c)
            ops = "OP_PUSHDATA";
        else if (op.op == 0x51)
            ops = "OP_TRUE";
        else
            ops = GetOpName(op.op);
        opsz = strlen(ops);
        op_sym = (text *)palloc(opsz + VARHDRSZ);
        memcpy(VARDATA(op_sym), ops, opsz);
        SET_VARSIZE(op_sym, opsz + VARHDRSZ);
        values[0] = PointerGetDatum(op_sym);

        /* op */
        values[1] = UInt32GetDatum(op.op);

        /* data */
        if (op.data.len > 0)
        {
            data = (bytea *) palloc(op.data.len + VARHDRSZ);
            SET_VARSIZE(data, op.data.len + VARHDRSZ);
            memcpy(VARDATA(data), op.data.p, op.data.len);
            values[2] = PointerGetDatum(data);
        } else
            nulls[2] = true;

		/* Build CTxOut tuple */
		tuple = heap_form_tuple(ctx->tupdesc, values, nulls);
		result = HeapTupleGetDatum(tuple);

        SRF_RETURN_NEXT(funcctx, result);
    }
    else
    {
        /* clean up */
        pfree(ctx->bp->buf);
        pfree(ctx->bp);
        pfree(ctx);

        SRF_RETURN_DONE(funcctx);
    }
}

PG_FUNCTION_INFO_V1(get_vout_arr);
Datum
get_vout_arr(PG_FUNCTION_ARGS)
{

    ArrayType     *result;
    TupleDesc     tupdesc;
    int16         typlen;
    bool          typbyval;
    char          typalign;
    Datum         *elems;
    bytea         *b_tx = PG_GETARG_BYTEA_P(0);
    struct const_buffer cbuf = { VARDATA(b_tx), VARSIZE(b_tx)-VARHDRSZ };
    struct bp_tx  *tx;
    int           i;
    Oid           arroid, tupoid;

    if (get_call_result_type(fcinfo, &arroid, NULL) != TYPEFUNC_SCALAR)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function called in context that cannot accept the return type")));

    /* arroid is an array, we need to get the type of the array element */
    tupoid = get_element_type(arroid);
    tupdesc = TypeGetTupleDesc(tupoid, NULL);
    tupdesc = BlessTupleDesc(tupdesc);

    tx = (struct bp_tx *)palloc(sizeof(struct bp_tx));
    bp_tx_init(tx);

    if (!deser_bp_tx(tx, &cbuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse transaction")));


    elems = (Datum *) palloc(sizeof(Datum) *  tx->vout->len);
    for (i = 0; i < tx->vout->len; i++)
    {
        struct bp_txout *txout;

		Datum		values[3];
		bool		nulls[3] = {false};
        HeapTuple   tuple;
        bytea       *pk;

        txout = parr_idx(tx->vout, i);

        /* n */
        values[0] = UInt32GetDatum(i);

        /* value */
        values[1] = Int64GetDatum(txout->nValue);

        /* scriptpubkey */
        pk = (bytea *) palloc(txout->scriptPubKey->len + VARHDRSZ);
        SET_VARSIZE(pk, txout->scriptPubKey->len + VARHDRSZ);
        memcpy(VARDATA(pk), txout->scriptPubKey->str, txout->scriptPubKey->len);
        values[2] = PointerGetDatum(pk);

		/* Build CTxOut tuple */
		tuple = heap_form_tuple(tupdesc, values, nulls);
		elems[i] = HeapTupleGetDatum(tuple);
    }

    get_typlenbyvalalign(tupdesc->tdtypeid, &typlen, &typbyval, &typalign);
    result = construct_array(elems, tx->vout->len, tupdesc->tdtypeid, typlen, typbyval, typalign);

    bp_tx_free(tx);
    pfree(tx);

    PG_RETURN_ARRAYTYPE_P(result);
}

PG_FUNCTION_INFO_V1(get_vin_arr);
Datum
get_vin_arr(PG_FUNCTION_ARGS)
{

    ArrayType     *result;
    TupleDesc     tupdesc;
    int16         typlen;
    bool          typbyval;
    char          typalign;
    Datum         *elems;
    bytea         *b_tx = PG_GETARG_BYTEA_P(0);
    struct const_buffer cbuf = { VARDATA(b_tx), VARSIZE(b_tx)-VARHDRSZ };
    struct bp_tx  *tx;
    int           i;
    Oid           arroid, tupoid;

    if (get_call_result_type(fcinfo, &arroid, NULL) != TYPEFUNC_SCALAR)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function called in context that cannot accept the return type")));

    /* arroid is an array, we need to get the type of the array element */
    tupoid = get_element_type(arroid);
    tupdesc = TypeGetTupleDesc(tupoid, NULL);
    tupdesc = BlessTupleDesc(tupdesc);

    tx = (struct bp_tx *)palloc(sizeof(struct bp_tx));
    bp_tx_init(tx);

    if (!deser_bp_tx(tx, &cbuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse transaction")));


    elems = (Datum *) palloc(sizeof(Datum) *  tx->vin->len);
    for (i = 0; i < tx->vin->len; i++)
    {
        struct bp_txin *txin;

		Datum		values[5];
		bool		nulls[5] = {false};
        HeapTuple   tuple;
        bytea       *poh;
        bytea       *sig;

        txin = parr_idx(tx->vin, i);

        /* n */
        values[0] = UInt32GetDatum(i);

        /* prevout_hash */
        poh = (bytea *) palloc(sizeof(bu256_t) + VARHDRSZ);
        SET_VARSIZE(poh, sizeof(bu256_t) + VARHDRSZ);
        memcpy(VARDATA(poh), &txin->prevout.hash, sizeof(bu256_t));
        values[1] = PointerGetDatum(poh);

        /* prevout_n */
        values[2] = UInt32GetDatum(txin->prevout.n);

        /* scriptsig */
        sig = (bytea *) palloc(txin->scriptSig->len + VARHDRSZ);
        SET_VARSIZE(sig, txin->scriptSig->len + VARHDRSZ);
        memcpy(VARDATA(sig), txin->scriptSig->str, txin->scriptSig->len);
        values[3] = PointerGetDatum(sig);

        /* sequence */
        values[4] = UInt32GetDatum(txin->nSequence);

		/* Build CTxIn tuple */
		tuple = heap_form_tuple(tupdesc, values, nulls);
		elems[i] = HeapTupleGetDatum(tuple);
    }

    get_typlenbyvalalign(tupdesc->tdtypeid, &typlen, &typbyval, &typalign);
    result = construct_array(elems, tx->vin->len, tupdesc->tdtypeid, typlen, typbyval, typalign);

    bp_tx_free(tx);
    pfree(tx);

    PG_RETURN_ARRAYTYPE_P(result);
}

PG_FUNCTION_INFO_V1(get_vin_outpt_arr);
Datum
get_vin_outpt_arr(PG_FUNCTION_ARGS)
{

    ArrayType     *result;
    TupleDesc     tupdesc;
    int16         typlen;
    bool          typbyval;
    char          typalign;
    Datum         *elems;
    bytea         *b_tx = PG_GETARG_BYTEA_P(0);
    struct const_buffer cbuf = { VARDATA(b_tx), VARSIZE(b_tx)-VARHDRSZ };
    struct bp_tx  *tx;
    int           i;
    Oid           arroid, tupoid;

    if (get_call_result_type(fcinfo, &arroid, NULL) != TYPEFUNC_SCALAR)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function called in context that cannot accept the return type")));

    /* arroid is an array, we need to get the type of the array element */
    tupoid = get_element_type(arroid);
    tupdesc = TypeGetTupleDesc(tupoid, NULL);
    tupdesc = BlessTupleDesc(tupdesc);

    tx = (struct bp_tx *)palloc(sizeof(struct bp_tx));
    bp_tx_init(tx);

    if (!deser_bp_tx(tx, &cbuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse transaction")));


    elems = (Datum *) palloc(sizeof(Datum) *  tx->vin->len);
    for (i = 0; i < tx->vin->len; i++)
    {
        struct bp_txin *txin;

		Datum		values[2];
		bool		nulls[2] = {false};
        HeapTuple   tuple;
        bytea       *poh;

        txin = parr_idx(tx->vin, i);

        /* prevout_hash */
        poh = (bytea *) palloc(sizeof(bu256_t) + VARHDRSZ);
        SET_VARSIZE(poh, sizeof(bu256_t) + VARHDRSZ);
        memcpy(VARDATA(poh), &txin->prevout.hash, sizeof(bu256_t));
        values[0] = PointerGetDatum(poh);

        /* prevout_n */
        values[1] = UInt32GetDatum(txin->prevout.n);

		/* Build COutPt tuple */
		tuple = heap_form_tuple(tupdesc, values, nulls);
		elems[i] = HeapTupleGetDatum(tuple);
    }

    get_typlenbyvalalign(tupdesc->tdtypeid, &typlen, &typbyval, &typalign);
    result = construct_array(elems, tx->vin->len, tupdesc->tdtypeid, typlen, typbyval, typalign);

    bp_tx_free(tx);
    pfree(tx);

    PG_RETURN_ARRAYTYPE_P(result);
}

PG_FUNCTION_INFO_V1(get_vin_outpt_jsonb);
Datum
get_vin_outpt_jsonb(PG_FUNCTION_ARGS)
{
    typedef struct JsonbInState
    {
        JsonbParseState *parseState;
        JsonbValue *res;
    } JsonbInState;

    bytea             *b_tx = PG_GETARG_BYTEA_P(0);
    JsonbInState      result;
    struct const_buffer cbuf = { VARDATA(b_tx), VARSIZE(b_tx)-VARHDRSZ };
    struct bp_tx  *tx;
    int               i;

    tx = (struct bp_tx *)palloc(sizeof(struct bp_tx));
    bp_tx_init(tx);

    if (!deser_bp_tx(tx, &cbuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse transaction")));

    memset(&result, 0, sizeof(JsonbInState));
    result.res = pushJsonbValue(&result.parseState, WJB_BEGIN_ARRAY, NULL);

    for (i = 0; i < tx->vin->len; i++)
    {
        struct bp_txin *txin;

        bytea       *poh;
        JsonbValue   jb;

        char *hash_key      = "hash";
        char *hash_val;

        char *n_key         = "n";
        char *n_val;
        int  n_len;

        txin = parr_idx(tx->vin, i);

        result.res = pushJsonbValue(&result.parseState, WJB_BEGIN_OBJECT, NULL);

        /* "hash" */
        jb.type = jbvString;
        jb.val.string.len = strlen(hash_key);
        jb.val.string.val = hash_key;
        result.res = pushJsonbValue(&result.parseState, WJB_KEY, &jb);

        /* prevout_hash */
        poh = (bytea *) palloc(sizeof(bu256_t) + VARHDRSZ);
        SET_VARSIZE(poh, sizeof(bu256_t) + VARHDRSZ);
        memcpy(VARDATA(poh), &txin->prevout.hash, sizeof(bu256_t));

        hash_val = DatumGetCString(DirectFunctionCall1(byteaout, PointerGetDatum(poh)));
        jb.type = jbvString;
        jb.val.string.len = strlen(hash_val);
        jb.val.string.val = hash_val;
        result.res = pushJsonbValue(&result.parseState, WJB_VALUE, &jb);

        /* "n" */
        jb.type = jbvString;
        jb.val.string.len = strlen(n_key);
        jb.val.string.val = n_key;
        result.res = pushJsonbValue(&result.parseState, WJB_KEY, &jb);

        /* prevout_n */
        n_len = snprintf(NULL, 0, "%d", txin->prevout.n);
        n_val = palloc(jb.val.string.len + 1);
        snprintf(n_val, n_len+1, "%d", txin->prevout.n);

        jb.type = jbvNumeric;
        jb.val.numeric = DatumGetNumeric(DirectFunctionCall3(numeric_in, CStringGetDatum(n_val), 0, -1));
        pfree(n_val);
        result.res = pushJsonbValue(&result.parseState, WJB_VALUE, &jb);

        result.res = pushJsonbValue(&result.parseState, WJB_END_OBJECT, NULL);
    }

    result.res = pushJsonbValue(&result.parseState, WJB_END_ARRAY, NULL);

    bp_tx_free(tx);
    pfree(tx);

    PG_RETURN_POINTER(JsonbValueToJsonb(result.res));
}

PG_FUNCTION_INFO_V1(get_vin_outpt_bytea);
Datum
get_vin_outpt_bytea(PG_FUNCTION_ARGS)
{

    ArrayType     *result;
    //TupleDesc     tupdesc;
    int16         typlen;
    bool          typbyval;
    char          typalign;
    Datum         *elems;
    bytea         *b_tx = PG_GETARG_BYTEA_P(0);
    struct const_buffer cbuf = { VARDATA(b_tx), VARSIZE(b_tx)-VARHDRSZ };
    struct bp_tx  *tx;
    int           i;

    if (get_call_result_type(fcinfo, NULL, NULL) != TYPEFUNC_SCALAR)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("function called in context that cannot accept the return type")));

    tx = (struct bp_tx *)palloc(sizeof(struct bp_tx));
    bp_tx_init(tx);

    if (!deser_bp_tx(tx, &cbuf))
        ereport(ERROR,
                (errcode(ERRCODE_DATA_EXCEPTION),
                 errmsg("unable to parse transaction")));

    elems = (Datum *) palloc(sizeof(Datum) *  tx->vin->len);
    for (i = 0; i < tx->vin->len; i++)
    {
        struct bp_txin *txin;
        bytea          *poh;
        uint32_t       nle;

        txin = parr_idx(tx->vin, i);
        nle = htobe32(txin->prevout.n);

        poh = (bytea *) palloc(sizeof(bu256_t) + sizeof(uint32_t) + VARHDRSZ);
        SET_VARSIZE(poh, sizeof(bu256_t) + sizeof(uint32_t) + VARHDRSZ);
        memcpy(VARDATA(poh), &txin->prevout.hash, sizeof(bu256_t));
        memcpy(VARDATA(poh)+sizeof(bu256_t), &nle, sizeof(uint32_t));
        elems[i] = PointerGetDatum(poh);
    }

    get_typlenbyvalalign(BYTEAOID, &typlen, &typbyval, &typalign);
    result = construct_array(elems, tx->vin->len, BYTEAOID, typlen, typbyval, typalign);

    bp_tx_free(tx);
    pfree(tx);

    PG_RETURN_ARRAYTYPE_P(result);
}
