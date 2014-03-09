CREATE KEYSPACE pgpkeys
    WITH replication = {'class': 'SimpleStrategy', 'replication_factor': 1};
USE pgpkeys;
CREATE TABLE keys (key blob PRIMARY KEY, keydata blob);
