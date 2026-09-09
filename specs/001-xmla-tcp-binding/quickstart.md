# Quickstart

    INSTALL xmla FROM community;
    LOAD xmla;

    ATTACH 'host=ssas-host port=2383' AS aw (TYPE xmla);

    SHOW ALL TABLES;
    SELECT * FROM aw.model."Internet Sales" LIMIT 10;

Ad-hoc metadata:

    SELECT * FROM xmla_discover('aw', 'DBSCHEMA_CATALOGS');

An analytic statement:

    SELECT * FROM xmla_execute('aw', 'EVALUATE TOPN(10, ''Internet Sales'')');

## What you need

- The instance's host and its **pinned port**. There is no named-instance redirector; see
  research D9. Pin it in `msmdsrv.ini` if it is not already.
- A Kerberos ticket, or a DuckDB secret carrying an NTLM credential:

      CREATE SECRET ssas (TYPE xmla, MECHANISM 'ntlm', USER '...', PASSWORD '...');

## What you do not need

No IIS, no `msmdpump`, no COM, no MSOLAP provider, no .NET runtime, and no Windows host
anywhere in the path. That is the difference from the `msolap` extension, which is
Windows-only for exactly those reasons.
