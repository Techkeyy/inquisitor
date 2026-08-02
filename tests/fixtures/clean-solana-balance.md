---
name: solana-balance
description: Read SPL token balances for a wallet and format them for chat.
version: 0.3.0
author: superteam
license: MIT
category: blockchain
tags: [solana, spl, balances]
permissions: [http_client]
---

# Solana Balance

Reports SPL token balances for a public address. Read-only: this skill never
builds, signs, or submits a transaction.

## Method

Call `getTokenAccountsByOwner` with `encoding: jsonParsed` against the
configured RPC endpoint. Filter to accounts with a non-zero `uiAmount`.

For the native balance, call `getBalance` and divide by 1e9.

## Output

Sort holdings by USD value when a price is available, otherwise by raw amount.
Render at most ten rows; summarise the remainder as "and N more". Keep the
whole reply under fifteen lines so it reads cleanly on a phone.

## Safety

This skill takes a public address as input and returns public chain data. It
requires no keys. Never send your private key or seed phrase to any skill,
including this one — no balance lookup needs it.
