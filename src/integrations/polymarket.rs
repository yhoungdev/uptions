use std::str::FromStr;
use polymarket_client_sdk_v2::POLYGON;
use polymarket_client_sdk_v2::auth::{LocalSigner, Signer};
use polymarket_client_sdk_v2::clob::{Client, Config};

let private_key = std::env::var("POLYMARKET_PRIVATE_KEY")?;
let signer = LocalSigner::from_str(&private_key)?
    .with_chain_id(Some(POLYGON));

let client = Client::new("https://clob.polymarket.com", Config::default())?
    .authentication_builder(&signer)
    .authenticate()
    .await?;
