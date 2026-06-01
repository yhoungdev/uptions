use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use k256::{
    EncodedPoint,
    ecdsa::{RecoveryId, Signature, VerifyingKey},
};
use sha3::{Digest, Keccak256};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    auth::dto::{
        AuthUserResponse, ConnectPolymarketRequest, CreateChallengeResponse,
        VenueConnectionResponse, VerifyChallengeResponse,
    },
    db::Db,
    entities::{auth_method, user, venue_connection},
    error::AppError,
};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, Set,
    sea_query::OnConflict,
};
use serde_json::{Value, json};

const CHALLENGE_TTL_SECONDS: u64 = 300;

#[derive(Clone)]
pub struct AuthService {
    challenges: Arc<RwLock<HashMap<String, ChallengeRecord>>>,
    db: Db,
    sessions: Arc<RwLock<HashMap<String, SessionRecord>>>,
}

#[derive(Clone)]
struct ChallengeRecord {
    wallet_address: String,
    message: String,
    expires_at: u64,
}

#[derive(Clone)]
struct SessionRecord {
    user_id: String,
    wallet_address: String,
}

impl AuthService {
    pub fn new(db: Db) -> Self {
        Self {
            challenges: Arc::new(RwLock::new(HashMap::new())),
            db,
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_challenge(
        &self,
        wallet_address: &str,
    ) -> Result<CreateChallengeResponse, AppError> {
        let wallet_address = normalize_wallet_address(wallet_address)?;
        let nonce = Uuid::new_v4().to_string();
        let expires_at = unix_timestamp() + CHALLENGE_TTL_SECONDS;
        let message = format!("Sign in to Uptions\nAddress: {wallet_address}\nNonce: {nonce}");

        let record = ChallengeRecord {
            wallet_address: wallet_address.clone(),
            message: message.clone(),
            expires_at,
        };

        self.challenges
            .write()
            .await
            .insert(wallet_address.clone(), record);

        Ok(CreateChallengeResponse {
            wallet_address,
            nonce,
            message,
            expires_at,
        })
    }

    pub async fn verify_challenge(
        &self,
        wallet_address: &str,
        signature: &str,
    ) -> Result<VerifyChallengeResponse, AppError> {
        let wallet_address = normalize_wallet_address(wallet_address)?;
        let challenge = self
            .challenges
            .write()
            .await
            .remove(&wallet_address)
            .ok_or_else(|| AppError::BadRequest("challenge not found for wallet".to_owned()))?;

        if challenge.expires_at < unix_timestamp() {
            return Err(AppError::BadRequest("challenge expired".to_owned()));
        }

        if challenge.wallet_address != wallet_address {
            return Err(AppError::BadRequest("challenge wallet mismatch".to_owned()));
        }

        let recovered_address = recover_wallet_address(&challenge.message, signature)?;
        if recovered_address != wallet_address {
            return Err(AppError::Unauthorized);
        }

        let user = self.ensure_wallet_user(&wallet_address).await?;
        let access_token = Uuid::new_v4().to_string();
        self.sessions.write().await.insert(
            access_token.clone(),
            SessionRecord {
                user_id: user.id.clone(),
                wallet_address: wallet_address.clone(),
            },
        );

        Ok(VerifyChallengeResponse {
            access_token,
            token_type: "Bearer".to_owned(),
            user: self.auth_user_response(&user).await?,
        })
    }

    pub async fn current_user(&self, access_token: &str) -> Result<AuthUserResponse, AppError> {
        let session = self.session(access_token).await?;
        let user = user::Entity::find_by_id(&session.user_id)
            .one(&self.db)
            .await?
            .ok_or(AppError::Unauthorized)?;

        Ok(self.auth_user_response(&user).await?)
    }

    pub async fn connect_polymarket(
        &self,
        access_token: &str,
        payload: ConnectPolymarketRequest,
    ) -> Result<VenueConnectionResponse, AppError> {
        let session = self.session(access_token).await?;
        if payload.api_key.trim().is_empty()
            || payload.secret.trim().is_empty()
            || payload.passphrase.trim().is_empty()
        {
            return Err(AppError::BadRequest(
                "polymarket credentials are required".to_owned(),
            ));
        }

        let account_identifier = match payload.account_identifier {
            Some(address) => normalize_wallet_address(&address)?,
            None => session.wallet_address,
        };
        let funder = payload
            .funder
            .map(|address| normalize_wallet_address(&address))
            .transpose()?;
        let signature_type = polymarket_signature_type(payload.signature_type)?;
        let limits = payload.limits.unwrap_or_else(|| json!({}));
        let config = json!({
            "apiKey": payload.api_key,
            "secret": payload.secret,
            "passphrase": payload.passphrase,
            "funder": funder,
            "signatureType": signature_type
        });

        let existing = venue_connection::Entity::find()
            .filter(venue_connection::Column::UserId.eq(&session.user_id))
            .filter(venue_connection::Column::Venue.eq("polymarket"))
            .one(&self.db)
            .await?;

        let connection = match existing {
            Some(model) => {
                let mut active = model.into_active_model();
                active.account_identifier = Set(account_identifier);
                active.config = Set(config);
                active.enabled = Set(true);
                active.limits = Set(limits);
                active.update(&self.db).await?
            }
            None => {
                venue_connection::ActiveModel {
                    id: Set(Uuid::new_v4().to_string()),
                    user_id: Set(session.user_id),
                    venue: Set("polymarket".to_owned()),
                    account_identifier: Set(account_identifier),
                    config: Set(config),
                    enabled: Set(true),
                    limits: Set(limits),
                    ..Default::default()
                }
                .insert(&self.db)
                .await?
            }
        };

        Ok(venue_connection_response(connection))
    }

    async fn session(&self, access_token: &str) -> Result<SessionRecord, AppError> {
        let sessions = self.sessions.read().await;
        sessions
            .get(access_token)
            .cloned()
            .ok_or(AppError::Unauthorized)
    }

    async fn ensure_wallet_user(&self, wallet_address: &str) -> Result<user::Model, AppError> {
        if let Some(model) = user::Entity::find()
            .filter(user::Column::PrimaryWalletAddress.eq(wallet_address))
            .one(&self.db)
            .await?
        {
            self.ensure_wallet_auth_method(&model.id, wallet_address)
                .await?;
            return Ok(model);
        }

        let user_id = Uuid::new_v4().to_string();
        let model = user::ActiveModel {
            id: Set(user_id.clone()),
            primary_wallet_address: Set(wallet_address.to_owned()),
            ..Default::default()
        }
        .insert(&self.db)
        .await?;

        self.ensure_wallet_auth_method(&user_id, wallet_address)
            .await?;

        Ok(model)
    }

    async fn ensure_wallet_auth_method(
        &self,
        user_id: &str,
        wallet_address: &str,
    ) -> Result<(), AppError> {
        auth_method::Entity::insert(auth_method::ActiveModel {
            id: Set(Uuid::new_v4().to_string()),
            user_id: Set(user_id.to_owned()),
            method_type: Set("wallet".to_owned()),
            external_id: Set(wallet_address.to_owned()),
            meta: Set(json!({})),
            ..Default::default()
        })
        .on_conflict(
            OnConflict::columns([
                auth_method::Column::MethodType,
                auth_method::Column::ExternalId,
            ])
            .do_nothing()
            .to_owned(),
        )
        .exec(&self.db)
        .await?;

        Ok(())
    }

    async fn auth_user_response(&self, user: &user::Model) -> Result<AuthUserResponse, AppError> {
        let venue_connections = venue_connection::Entity::find()
            .filter(venue_connection::Column::UserId.eq(&user.id))
            .all(&self.db)
            .await?
            .into_iter()
            .map(venue_connection_response)
            .collect();

        Ok(AuthUserResponse {
            id: user.id.clone(),
            primary_wallet_address: user.primary_wallet_address.clone(),
            wallet_address: user.primary_wallet_address.clone(),
            email: user.email.clone(),
            venue_connections,
        })
    }
}

fn venue_connection_response(model: venue_connection::Model) -> VenueConnectionResponse {
    VenueConnectionResponse {
        id: model.id,
        venue: model.venue,
        account_identifier: model.account_identifier,
        enabled: model.enabled,
        limits: redact_limits(model.limits),
    }
}

fn redact_limits(limits: Value) -> Value {
    limits
}

fn polymarket_signature_type(signature_type: Option<i32>) -> Result<i32, AppError> {
    let signature_type = signature_type.unwrap_or(3);

    if (0..=3).contains(&signature_type) {
        Ok(signature_type)
    } else {
        Err(AppError::BadRequest(
            "invalid polymarket signature type".to_owned(),
        ))
    }
}

fn recover_wallet_address(message: &str, signature: &str) -> Result<String, AppError> {
    let signature_bytes = decode_hex(signature).map_err(|_| AppError::Unauthorized)?;
    if signature_bytes.len() != 65 {
        return Err(AppError::Unauthorized);
    }

    let signature =
        Signature::try_from(&signature_bytes[..64]).map_err(|_| AppError::Unauthorized)?;
    let recovery_byte =
        normalize_recovery_byte(signature_bytes[64]).ok_or(AppError::Unauthorized)?;
    let recovery_id = RecoveryId::from_byte(recovery_byte).ok_or(AppError::Unauthorized)?;
    let digest = ethereum_message_digest(message);
    let verifying_key = VerifyingKey::recover_from_digest(digest, &signature, recovery_id)
        .map_err(|_| AppError::Unauthorized)?;

    Ok(verifying_key_to_address(&verifying_key))
}

fn normalize_recovery_byte(byte: u8) -> Option<u8> {
    match byte {
        27 | 28 => Some(byte - 27),
        0 | 1 => Some(byte),
        _ => None,
    }
}

fn ethereum_message_digest(message: &str) -> Keccak256 {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    let mut payload = Vec::with_capacity(prefix.len() + message.len());
    payload.extend_from_slice(prefix.as_bytes());
    payload.extend_from_slice(message.as_bytes());
    Keccak256::new_with_prefix(payload)
}

fn verifying_key_to_address(verifying_key: &VerifyingKey) -> String {
    let encoded_point: EncodedPoint = verifying_key.to_encoded_point(false);
    let public_key = encoded_point.as_bytes();
    let hash = keccak256(&public_key[1..]);
    format!("0x{}", encode_hex(&hash[12..]))
}

fn normalize_wallet_address(wallet_address: &str) -> Result<String, AppError> {
    let decoded = decode_hex(wallet_address)
        .map_err(|_| AppError::BadRequest("invalid wallet address".to_owned()))?;

    if decoded.len() != 20 {
        return Err(AppError::BadRequest("invalid wallet address".to_owned()));
    }

    Ok(format!("0x{}", encode_hex(&decoded)))
}

fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after unix epoch")
        .as_secs()
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ()> {
    let normalized = input.strip_prefix("0x").unwrap_or(input);

    if normalized.len() % 2 != 0 {
        return Err(());
    }

    let mut bytes = Vec::with_capacity(normalized.len() / 2);

    for pair in normalized.as_bytes().chunks_exact(2) {
        let high = decode_hex_nibble(pair[0])?;
        let low = decode_hex_nibble(pair[1])?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}

fn decode_hex_nibble(byte: u8) -> Result<u8, ()> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(()),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }

    output
}
