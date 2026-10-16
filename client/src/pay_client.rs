//! The buyer's end-to-end flow and local wallet (§20).
//!
//! `buy` blinds tokens and opens an order; the user pays the printed Monero
//! address; `collect` turns the confirmed payment into unblinded tokens; and
//! `redeem` spends one token for a VPN access grant. Tokens and in-flight orders
//! live in a small JSON wallet on disk. Nothing here ever sends an identity.

use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::payment::{self, PendingToken};

// ---------------------------------------------------------------------------
// Wallet
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Default)]
pub struct Wallet {
    pub pending: Vec<PendingOrder>,
    pub tokens: Vec<Token>,
}

/// An order whose payment may not have cleared yet. Holds the blinding secrets
/// so the tokens can be finalized once the mint signs them.
#[derive(Serialize, Deserialize)]
pub struct PendingOrder {
    pub order_id: String,
    pub denom: String,
    pub pubkey_pem: String,
    pub toks: Vec<PendingTok>,
}

#[derive(Serialize, Deserialize)]
pub struct PendingTok {
    pub nonce_b64: String,
    pub secret_b64: String,
    pub blind_b64: String,
}

/// A spendable, unblinded token: a nonce and the mint's signature over it.
#[derive(Serialize, Deserialize)]
pub struct Token {
    pub denom: String,
    pub nonce_b64: String,
    pub sig_b64: String,
}

/// Default wallet path: $HOME/.pqanon/wallet.json (or ./pqanon-wallet.json).
pub fn default_wallet_path() -> PathBuf {
    if let Ok(home) = std::env::var("HOME") {
        return PathBuf::from(home).join(".pqanon").join("wallet.json");
    }
    PathBuf::from("pqanon-wallet.json")
}

fn load_wallet(path: &Path) -> Result<Wallet> {
    match std::fs::read(path) {
        // An absent, empty, or whitespace-only file is just an empty wallet.
        Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => Ok(Wallet::default()),
        Ok(bytes) => Ok(serde_json::from_slice(&bytes).context("parsing wallet")?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Wallet::default()),
        Err(e) => Err(e).context("reading wallet"),
    }
}

fn save_wallet(path: &Path, w: &Wallet) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).ok();
    }
    let data = serde_json::to_vec_pretty(w)?;
    std::fs::write(path, data).context("writing wallet")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// HTTP helpers (surface the server's error message on non-2xx)
// ---------------------------------------------------------------------------

fn http_get(url: &str) -> Result<serde_json::Value> {
    match ureq::get(url).call() {
        Ok(resp) => Ok(resp.into_json()?),
        Err(ureq::Error::Status(code, resp)) => {
            let body = resp.into_string().unwrap_or_default();
            Err(anyhow!("GET {url} → {code}: {body}"))
        }
        Err(e) => Err(anyhow!("GET {url}: {e}")),
    }
}

fn http_post(url: &str, body: serde_json::Value) -> Result<serde_json::Value> {
    match ureq::post(url).send_json(body) {
        Ok(resp) => Ok(resp.into_json()?),
        Err(ureq::Error::Status(code, resp)) => {
            let b = resp.into_string().unwrap_or_default();
            Err(anyhow!("POST {url} → {code}: {b}"))
        }
        Err(e) => Err(anyhow!("POST {url}: {e}")),
    }
}

fn base(server: &str) -> String {
    server.trim_end_matches('/').to_string()
}

// ---------------------------------------------------------------------------
// Flow
// ---------------------------------------------------------------------------

/// Fetch the plan's public key PEM from the mint.
fn denomination_key(server: &str, plan: &str) -> Result<String> {
    let v = http_get(&format!("{}/api/pay/denominations", base(server)))?;
    let denoms = v["denominations"]
        .as_array()
        .ok_or_else(|| anyhow!("malformed denominations response"))?;
    for d in denoms {
        if d["id"].as_str() == Some(plan) {
            return Ok(d["public_key_pem"]
                .as_str()
                .ok_or_else(|| anyhow!("denomination missing public key"))?
                .to_string());
        }
    }
    Err(anyhow!(
        "unknown plan {plan:?}; run `pqanon plans --server {server}` to list them"
    ))
}

/// List the plans on sale and the payment rails available.
pub fn plans(server: &str) -> Result<()> {
    let v = http_get(&format!("{}/api/pay/denominations", base(server)))?;
    let rails: Vec<String> = v["rails"]
        .as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str().map(String::from)).collect())
        .unwrap_or_default();
    println!(
        "Payment rails: {} (default: {})",
        if rails.is_empty() { "?".into() } else { rails.join(", ") },
        v["default_rail"].as_str().unwrap_or("?")
    );
    println!("{:<10} {:<10} {:>14} {:>16}", "PLAN", "DURATION", "PRICE (XMR)", "PRICE (BTC)");
    for d in v["denominations"].as_array().cloned().unwrap_or_default() {
        println!(
            "{:<10} {:<10} {:>14} {:>16}",
            d["id"].as_str().unwrap_or("?"),
            format!("{}d", d["duration_days"].as_i64().unwrap_or(0)),
            d["price_xmr"].as_str().unwrap_or("?"),
            d["price_btc"].as_str().unwrap_or("?"),
        );
    }
    Ok(())
}

/// Blind `count` tokens for `plan`, open an order on `rail` (or the server
/// default), and record it in the wallet. Prints the address to pay.
pub fn buy(server: &str, plan: &str, count: usize, rail: Option<&str>, wallet_path: &Path) -> Result<()> {
    let count = count.clamp(1, 50);
    let pem = denomination_key(server, plan)?;
    let pk = payment::load_pubkey(&pem)?;

    // Blind `count` fresh nonces.
    let mut pending: Vec<PendingToken> = Vec::with_capacity(count);
    let mut blinded_b64: Vec<String> = Vec::with_capacity(count);
    for _ in 0..count {
        let nonce = payment::new_nonce();
        let p = payment::blind_nonce(&pk, &nonce)?;
        blinded_b64.push(B64.encode(&p.blind_message));
        pending.push(p);
    }

    // Open the order (rail omitted → server default).
    let mut body = serde_json::json!({ "denom": plan, "blinded_tokens": blinded_b64 });
    if let Some(r) = rail {
        body["rail"] = serde_json::Value::String(r.to_string());
    }
    let resp = http_post(&format!("{}/api/pay/order", base(server)), body)?;
    let order_id = resp["id"].as_str().ok_or_else(|| anyhow!("no order id"))?.to_string();

    // Persist the pending order (blinding secrets included) so we can finalize
    // after payment, even in a later process.
    let mut wallet = load_wallet(wallet_path)?;
    wallet.pending.push(PendingOrder {
        order_id: order_id.clone(),
        denom: plan.to_string(),
        pubkey_pem: pem,
        toks: pending
            .iter()
            .map(|p| PendingTok {
                nonce_b64: B64.encode(&p.nonce),
                secret_b64: B64.encode(&p.secret),
                blind_b64: B64.encode(&p.blind_message),
            })
            .collect(),
    });
    save_wallet(wallet_path, &wallet)?;

    println!("Order {order_id} — pay to stay anonymous:\n");
    println!("  Rail:    {}", resp["rail"].as_str().unwrap_or("?"));
    println!("  Amount:  {}", resp["amount_label"].as_str().unwrap_or("?"));
    println!("  Address: {}", resp["address"].as_str().unwrap_or("?"));
    if let Some(uri) = resp["uri"].as_str() {
        println!("  URI:     {uri}");
    }
    println!(
        "\nAfter the payment confirms, run:\n  pqanon collect --order {order_id} --server {server}"
    );
    Ok(())
}

/// Check an order's status and, once paid, collect and unblind its tokens.
pub fn collect(server: &str, order_id: &str, wallet_path: &Path) -> Result<()> {
    let mut wallet = load_wallet(wallet_path)?;
    let idx = wallet
        .pending
        .iter()
        .position(|o| o.order_id == order_id)
        .ok_or_else(|| anyhow!("order {order_id} not found in wallet"))?;

    // Status first, so we can report clearly if payment hasn't cleared.
    let status = http_get(&format!("{}/api/pay/order/{}", base(server), order_id))?;
    let st = status["status"].as_str().unwrap_or("?");
    if st != "paid" && st != "collected" {
        println!("Order {order_id} is {st}; nothing to collect yet.");
        if let Some(addr) = status["address"].as_str() {
            println!("Pay {} to {addr}", status["amount_label"].as_str().unwrap_or("?"));
        }
        return Ok(());
    }

    let resp = http_post(
        &format!("{}/api/pay/collect", base(server)),
        serde_json::json!({ "order_id": order_id }),
    )?;
    let sigs = resp["signatures"].as_array().ok_or_else(|| anyhow!("no signatures"))?;

    let order = &wallet.pending[idx];
    let pk = payment::load_pubkey(&order.pubkey_pem)?;
    if sigs.len() != order.toks.len() {
        return Err(anyhow!(
            "mint returned {} signatures for {} tokens",
            sigs.len(),
            order.toks.len()
        ));
    }

    let mut new_tokens = Vec::with_capacity(sigs.len());
    for (sig_v, pt) in sigs.iter().zip(order.toks.iter()) {
        let blind_sig = B64.decode(sig_v.as_str().unwrap_or_default())?;
        let pending = PendingToken {
            nonce: B64.decode(&pt.nonce_b64)?,
            secret: B64.decode(&pt.secret_b64)?,
            blind_message: B64.decode(&pt.blind_b64)?,
        };
        let sig = payment::finalize_token(&pk, &pending, &blind_sig)?;
        payment::verify_token(&pk, &pending.nonce, &sig)?; // belt and braces
        new_tokens.push(Token {
            denom: order.denom.clone(),
            nonce_b64: pt.nonce_b64.clone(),
            sig_b64: B64.encode(&sig),
        });
    }

    let n = new_tokens.len();
    let denom = order.denom.clone();
    wallet.tokens.extend(new_tokens);
    wallet.pending.remove(idx);
    save_wallet(wallet_path, &wallet)?;
    println!("Collected {n} {denom} token(s). Redeem one with:\n  pqanon redeem --plan {denom} --server {server}");
    Ok(())
}

/// Show the tokens held in the wallet.
pub fn list_tokens(wallet_path: &Path) -> Result<()> {
    let wallet = load_wallet(wallet_path)?;
    use std::collections::BTreeMap;
    let mut by_denom: BTreeMap<String, usize> = BTreeMap::new();
    for t in &wallet.tokens {
        *by_denom.entry(t.denom.clone()).or_default() += 1;
    }
    if by_denom.is_empty() {
        println!("No tokens. Buy some with `pqanon buy --plan <plan> --server <url>`.");
    } else {
        println!("Spendable tokens:");
        for (denom, n) in by_denom {
            println!("  {denom:<10} {n}");
        }
    }
    if !wallet.pending.is_empty() {
        println!("Pending orders (awaiting payment / collection):");
        for o in &wallet.pending {
            println!("  {} ({}, {} token(s))", o.order_id, o.denom, o.toks.len());
        }
    }
    Ok(())
}

/// Spend one token of `plan` for a VPN access grant.
pub fn redeem(server: &str, plan: &str, wallet_path: &Path) -> Result<()> {
    let mut wallet = load_wallet(wallet_path)?;
    let idx = wallet
        .tokens
        .iter()
        .position(|t| t.denom == plan)
        .ok_or_else(|| anyhow!("no {plan} tokens in wallet; buy one first"))?;
    let token = &wallet.tokens[idx];

    let resp = http_post(
        &format!("{}/api/pay/redeem", base(server)),
        serde_json::json!({
            "denom": token.denom,
            "token": token.nonce_b64,
            "signature": token.sig_b64,
        }),
    )?;

    // Spend succeeded — drop the token so it is never reused.
    let denom = token.denom.clone();
    wallet.tokens.remove(idx);
    save_wallet(wallet_path, &wallet)?;

    println!("Redeemed a {denom} token. VPN access granted:");
    println!("  session: {}", resp["session_id"].as_str().unwrap_or("?"));
    println!("  expires: {}", resp["expires_at"].as_str().unwrap_or("?"));
    println!("  grant:   {}", resp["grant"].as_str().unwrap_or("?"));
    println!("\nThis grant is unlinkable to your payment. Present it to the tunnel to connect.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_or_missing_wallet_loads_as_default() {
        let dir = std::env::temp_dir().join(format!("pqanon-wtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let missing = dir.join("missing.json");
        assert!(load_wallet(&missing).unwrap().tokens.is_empty());

        // An empty file (as `mktemp` leaves) must not error.
        let empty = dir.join("empty.json");
        std::fs::write(&empty, b"").unwrap();
        assert!(load_wallet(&empty).unwrap().tokens.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn wallet_roundtrips() {
        let dir = std::env::temp_dir().join(format!("pqanon-wtest2-{}", std::process::id()));
        let path = dir.join("wallet.json");
        let mut w = Wallet::default();
        w.tokens.push(Token {
            denom: "month".into(),
            nonce_b64: "AAAA".into(),
            sig_b64: "BBBB".into(),
        });
        save_wallet(&path, &w).unwrap();
        let back = load_wallet(&path).unwrap();
        assert_eq!(back.tokens.len(), 1);
        assert_eq!(back.tokens[0].denom, "month");
        std::fs::remove_dir_all(&dir).ok();
    }
}
