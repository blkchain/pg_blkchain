# pg_blkchain
PostgreSQL Blockchain Extension

WARNING: This is work-in-progress, use at your own risk!

This is a C language Postgres extension that provides Bitcoin
blockchain functionality.


## What You Can Do ##

```sql
CREATE EXTENSION pg_blkchain;
```

```sql
SELECT op_sym, encode(data, 'escape')
  FROM parse_script(E'\\x04ffff001d0104455468652054696d65732030332f4a616e2f32'::bytea ||
                    E'\\x303039204368616e63656c6c6f72206f6e206272696e6b206f66'::bytea ||
                    E'\\x207365636f6e64206261696c6f757420666f722062616e6b73'::bytea);
   op_sym    |                                encode
-------------+-----------------------------------------------------------------------
 OP_PUSHDATA | \377\377\000\x1D
 OP_PUSHDATA | \x04
 OP_PUSHDATA | The Times 03/Jan/2009 Chancellor on brink of second bailout for banks
(3 rows)
```

or

Assuming you have a table with a `BYTEA` column named `tx`,
which contains transactions, you can do stuff like:

```sql
  -- Note: this requires the pgcrypto extension for digest().

  SELECT n_in, verify_sig(tx, ptx, n_in)
   FROM (
    SELECT (vin).n n_in, p.tx ptx, x.tx tx
      FROM (
        SELECT get_vin(tx) vin, tx
          FROM rtxs
        WHERE id = 37898
      ) x
    JOIN rtxs p
      ON (vin).prevout_hash = digest(digest(p.tx, 'sha256'), 'sha256')
   ) x;
 n_in | verify_sig
------+------------
    0 | t
    1 | t
```

or

```sql

SELECT parse_script((get_vout(tx)).scriptpubkey) FROM rtxs WHERE id = 37898;
                          parse_script
----------------------------------------------------------------
 (OP_DUP,118,)
 (OP_HASH160,169,)
 (OP_PUSHDATA,20,"\\x32b0f5cad60641be97317b3f013ce53f60893448")
 (OP_EQUALVERIFY,136,)
 (OP_CHECKSIG,172,)
(5 rows)

```

```sql
-- Note: this will take a while to run!

SELECT (parse_script((get_vout(tx)).scriptpubkey)).op_sym, count(1)
FROM rtxs
GROUP BY op_sym
ORDER BY count(1) DESC LIMIT 10;
         op_sym         |   count
------------------------+-----------
 OP_PUSHDATA            | 678204416
 OP_HASH160             | 672704434
 OP_CHECKSIG            | 598508189
 OP_EQUALVERIFY         | 597189173
 OP_DUP                 | 597189166
 OP_EQUAL               |  75515405
 OP_RETURN              |   3017195
 OP_CHECKMULTISIG       |    574881
 OP_TRUE                |    572552
 OP_9                   |      2635
```

More details to follow. This [blog post](https://grisha.org/blog/2017/10/20/blockchain-in-postgresql-part-2/)
has some more info.

If you find this interesting, comment here in an issue or on twitter
@humblehack, whatever. Also if you'd like to help.

## Building ##

This extension requires
[github.com/jgarzik/picocoin](https://github.com/jgarzik/picocoin).
(No, we do not endorse SegWit2X, this is the only functional C library
that I could find. If you have a better idea, let me know).

Building picocoin is relatively simple, you will need to first
`git clone https://github.com/bitcoin-core/secp256k1` into the `external`
subdirectory and build it. It seems to suggest a particular git hash, but I just
used the latest and it works.

Once you have picocoin installed, you should be able to just

```
make
sudo make install
```

This was developed and tested only on PG 9.6.
