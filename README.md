# Applied Cryptography Project
### Two Clients Exchanging Messages With Server
- Each client with its own suite for (Hashing, Key Exchange, Digital Signature, Symmetric Encryption) => sends it to server
- Server handles each client's suite, signs the shared key, then sends it back to the corresponding client
- Each message is encrypted with the suite's Symmetric Encryption Algorithm
