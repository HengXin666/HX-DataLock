# Keyring Is Private

Status: accepted. Supersedes the storage sentence in ADR 0001.

A Keyring holds the encrypted Read Key, so anyone who copies it can guess the Master Password offline. The default is a private local file. The Public Key Document is the only artifact meant for public storage, a static site, or a repository.

Creating a Keyring that the caller intends to publish is an explicit option. That path prints a danger warning and refuses any Master Password under about 80 estimated bits. `--allow-weak` does not lower that floor. The file format stays `hxdl.keyring.v1`; publicity is a creation policy, not a new schema.
