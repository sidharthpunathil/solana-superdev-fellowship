use actix_web::{web, App, HttpResponse, HttpServer, Responder, Error};
use serde::{Deserialize, Serialize};
use ed25519_dalek::Keypair;
use rand::rngs::OsRng;
use bs58;
use base64;
use solana_sdk::pubkey::Pubkey;
use spl_token::instruction::initialize_mint;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use actix_web::dev::Payload;
use actix_web::http::StatusCode;
use actix_web::FromRequest;
use futures_util::future::{ready, Ready};
use std::future::Future;
use std::pin::Pin;
use serde::de::DeserializeOwned;

#[derive(Serialize)]
struct SuccessResponse<T> {
    success: bool,
    data: T,
}

#[derive(Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
}

#[derive(Serialize)]
struct KeypairResponse {
    pubkey: String,
    secret: String,
}

#[derive(Deserialize)]
struct TokenCreateRequest {
    mintAuthority: String,
    mint: String,
    decimals: u8,
}

#[derive(Serialize, Clone)]
struct TokenAccountMeta {
    pubkey: String,
    #[serde(rename = "is_signer")]
    is_signer: bool,
    #[serde(rename = "is_writable")]
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenCreateResponse {
    program_id: String,
    accounts: TokenAccountMeta,
    instruction_data: String,
}

#[derive(Deserialize)]
struct TokenMintRequest {
    mint: String,
    destination: String,
    authority: String,
    amount: u64,
}

#[derive(Serialize)]
struct TokenMintAccountMeta {
    pubkey: String,
    #[serde(rename = "is_signer")]
    is_signer: bool,
    #[serde(rename = "is_writable")]
    is_writable: bool,
}

#[derive(Serialize)]
struct TokenMintData {
    program_id: String,
    accounts: Vec<TokenMintAccountMeta>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct MessageSignRequest {
    message: String,
    secret: String,
}

#[derive(Serialize)]
struct MessageSignResponse {
    signature: String,
    public_key: String,
    message: String,
}

#[derive(Deserialize)]
struct MessageVerifyRequest {
    message: String,
    signature: String,
    pubkey: String,
}

#[derive(Serialize)]
struct MessageVerifyResponse {
    valid: bool,
    message: String,
    pubkey: String,
}

#[derive(Deserialize)]
struct SendSolRequest {
    from: String,
    to: String,
    lamports: u64,
}

#[derive(Serialize)]
struct SendSolResponse {
    program_id: String,
    accounts: Vec<String>,
    instruction_data: String,
}

#[derive(Deserialize)]
struct SendTokenRequest {
    destination: String,
    mint: String,
    owner: String,
    amount: u64,
}

#[derive(Serialize)]
struct SendTokenAccountMeta {
    pubkey: String,
    #[serde(rename = "is_signer")]
    is_signer: bool,
}

#[derive(Serialize)]
struct SendTokenResponse {
    program_id: String,
    accounts: Vec<SendTokenAccountMeta>,
    instruction_data: String,
}

// Custom extractor for consistent error responses on deserialization failure
pub struct MyJson<T>(pub T);

impl<T> FromRequest for MyJson<T>
where
    T: DeserializeOwned + 'static,
{
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, payload: &mut Payload) -> Self::Future {
        let fut = web::Json::<T>::from_request(req, payload);
        Box::pin(async move {
            match fut.await {
                Ok(json) => Ok(MyJson(json.into_inner())),
                Err(_) => {
                    let err = ErrorResponse {
                        success: false,
                        error: "Invalid request format or missing required fields".to_string(),
                    };
                    let resp = HttpResponse::BadRequest().json(err);
                    Err(actix_web::error::InternalError::from_response("", resp).into())
                }
            }
        })
    }
}

async fn health() -> impl Responder {
    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: serde_json::json!({"status": "ok"}),
    })
}

async fn keypair() -> impl Responder {
    let mut csprng = OsRng {};
    let keypair = Keypair::generate(&mut csprng);
    let pubkey = bs58::encode(keypair.public.as_bytes()).into_string();
    let mut secret_bytes = Vec::new();
    secret_bytes.extend_from_slice(&keypair.secret.to_bytes());
    secret_bytes.extend_from_slice(&keypair.public.to_bytes());
    let secret = bs58::encode(secret_bytes).into_string();

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: KeypairResponse { pubkey, secret },
    })
}

async fn token_create(payload: web::Bytes) -> impl Responder {
    let value: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid request format".to_string(),
            });
        }
    };
    // Check required fields
    if !value.get("mintAuthority").is_some() || !value.get("mint").is_some() || !value.get("decimals").is_some() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        });
    }
    let req: TokenCreateRequest = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid request format".to_string(),
            });
        }
    };
    // Parse base58 pubkeys
    let mint_pubkey = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid mint pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for mint pubkey".to_string(),
            });
        }
    };
    let mint_authority_pubkey = match bs58::decode(&req.mintAuthority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid mintAuthority pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for mintAuthority pubkey".to_string(),
            });
        }
    };

    // Build the instruction (freeze_authority is None for now)
    let ix = match initialize_mint(
        &spl_token::id(),
        &mint_pubkey,
        &mint_authority_pubkey,
        None,
        req.decimals,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: format!("Failed to build instruction: {}", e),
            });
        }
    };

    // Prepare accounts (return only the first account as object)
    let accounts: Vec<TokenAccountMeta> = ix.accounts.iter().map(|meta| TokenAccountMeta {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();
    let account_obj = accounts.get(0).cloned().unwrap_or(TokenAccountMeta {
        pubkey: String::new(),
        is_signer: false,
        is_writable: false,
    });

    // Encode instruction data as base64
    let instruction_data = base64::encode(&ix.data);

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: TokenCreateResponse {
            program_id: ix.program_id.to_string(),
            accounts: account_obj,
            instruction_data,
        },
    })
}

async fn token_mint(req: MyJson<TokenMintRequest>) -> impl Responder {
    let req = req.0;
    // Parse base58 pubkeys
    let mint_pubkey = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid mint pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for mint pubkey".to_string(),
            });
        }
    };
    let destination_pubkey = match bs58::decode(&req.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid destination pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for destination pubkey".to_string(),
            });
        }
    };
    let authority_pubkey = match bs58::decode(&req.authority).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid authority pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for authority pubkey".to_string(),
            });
        }
    };

    // Build the instruction
    let ix = match spl_token::instruction::mint_to(
        &spl_token::id(),
        &mint_pubkey,
        &destination_pubkey,
        &authority_pubkey,
        &[], // multisig signers
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: format!("Failed to build instruction: {}", e),
            });
        }
    };

    // Prepare accounts
    let accounts: Vec<TokenMintAccountMeta> = ix.accounts.iter().map(|meta| TokenMintAccountMeta {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
        is_writable: meta.is_writable,
    }).collect();

    // Encode instruction data as base64
    let instruction_data = base64::encode(&ix.data);

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: TokenMintData {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    })
}

async fn message_sign(req: MyJson<MessageSignRequest>) -> impl Responder {
    let req = req.0;
    if req.message.is_empty() || req.secret.is_empty() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        });
    }
    let secret_bytes = match bs58::decode(&req.secret).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for secret key".to_string(),
            });
        }
    };
    let secret = if secret_bytes.len() == 32 {
        match ed25519_dalek::SecretKey::from_bytes(&secret_bytes) {
            Ok(sk) => sk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid secret key bytes".to_string(),
                });
            }
        }
    } else if secret_bytes.len() == 64 {
        match ed25519_dalek::SecretKey::from_bytes(&secret_bytes[0..32]) {
            Ok(sk) => sk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid secret key bytes".to_string(),
                });
            }
        }
    } else {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Secret key must be 32 or 64 bytes".to_string(),
        });
    };
    let public = ed25519_dalek::PublicKey::from(&secret);
    let keypair = ed25519_dalek::Keypair { secret, public };
    let signature = keypair.sign(req.message.as_bytes());
    let signature_b64 = base64::encode(signature.to_bytes());
    let public_b58 = bs58::encode(keypair.public.as_bytes()).into_string();
    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: MessageSignResponse {
            signature: signature_b64,
            public_key: public_b58,
            message: req.message.clone(),
        },
    })
}

async fn message_verify(payload: web::Bytes) -> impl Responder {
    let value: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid request format".to_string(),
            });
        }
    };
    // Check required fields
    if !value.get("message").is_some() || !value.get("signature").is_some() || !value.get("pubkey").is_some() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        });
    }
    let req: MessageVerifyRequest = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid request format".to_string(),
            });
        }
    };
    // Decode public key from base58
    let pubkey_bytes = match bs58::decode(&req.pubkey).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for pubkey".to_string(),
            });
        }
    };
    let public = match ed25519_dalek::PublicKey::from_bytes(&pubkey_bytes) {
        Ok(pk) => pk,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid public key bytes".to_string(),
            });
        }
    };

    // Decode signature from base64
    let signature_bytes = match base64::decode(&req.signature) {
        Ok(bytes) => bytes,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base64 for signature".to_string(),
            });
        }
    };
    let signature = match ed25519_dalek::Signature::from_bytes(&signature_bytes) {
        Ok(sig) => sig,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid signature bytes".to_string(),
            });
        }
    };

    // Verify the signature
    let valid = public.verify(req.message.as_bytes(), &signature).is_ok();

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: MessageVerifyResponse {
            valid,
            message: req.message.clone(),
            pubkey: req.pubkey.clone(),
        },
    })
}

async fn send_sol(req: MyJson<SendSolRequest>) -> impl Responder {
    let req = req.0;
    // Validate base58 addresses
    let from_pubkey = match bs58::decode(&req.from).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid from pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for from pubkey".to_string(),
            });
        }
    };
    let to_pubkey = match bs58::decode(&req.to).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid to pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for to pubkey".to_string(),
            });
        }
    };

    // Build the transfer instruction
    let ix = solana_sdk::system_instruction::transfer(
        &from_pubkey,
        &to_pubkey,
        req.lamports,
    );

    // Prepare accounts
    let accounts = ix.accounts.iter().map(|meta| meta.pubkey.to_string()).collect();

    // Encode instruction data as base64
    let instruction_data = base64::encode(&ix.data);

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: SendSolResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    })
}

async fn send_token(payload: web::Bytes) -> impl Responder {
    let value: serde_json::Value = match serde_json::from_slice(&payload) {
        Ok(v) => v,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid request format".to_string(),
            });
        }
    };
    // Check required fields
    if !value.get("destination").is_some() || !value.get("mint").is_some() || !value.get("owner").is_some() || !value.get("amount").is_some() {
        return HttpResponse::BadRequest().json(ErrorResponse {
            success: false,
            error: "Missing required fields".to_string(),
        });
    }
    let req: SendTokenRequest = match serde_json::from_value(value) {
        Ok(r) => r,
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid request format".to_string(),
            });
        }
    };
    // Validate base58 addresses
    let destination_pubkey = match bs58::decode(&req.destination).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid destination pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for destination pubkey".to_string(),
            });
        }
    };
    let mint_pubkey = match bs58::decode(&req.mint).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid mint pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for mint pubkey".to_string(),
            });
        }
    };
    let owner_pubkey = match bs58::decode(&req.owner).into_vec() {
        Ok(bytes) => match Pubkey::try_from(bytes.as_slice()) {
            Ok(pk) => pk,
            Err(_) => {
                return HttpResponse::BadRequest().json(ErrorResponse {
                    success: false,
                    error: "Invalid owner pubkey".to_string(),
                });
            }
        },
        Err(_) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: "Invalid base58 for owner pubkey".to_string(),
            });
        }
    };

    // Build the transfer instruction
    let ix = match spl_token::instruction::transfer(
        &spl_token::id(),
        &mint_pubkey, // source (should be associated token account, but using mint for demo)
        &destination_pubkey,
        &owner_pubkey,
        &[], // multisig signers
        req.amount,
    ) {
        Ok(ix) => ix,
        Err(e) => {
            return HttpResponse::BadRequest().json(ErrorResponse {
                success: false,
                error: format!("Failed to build instruction: {}", e),
            });
        }
    };

    // Prepare accounts (only pubkey and is_signer)
    let accounts: Vec<SendTokenAccountMeta> = ix.accounts.iter().map(|meta| SendTokenAccountMeta {
        pubkey: meta.pubkey.to_string(),
        is_signer: meta.is_signer,
    }).collect();

    // Encode instruction data as base64
    let instruction_data = base64::encode(&ix.data);

    HttpResponse::Ok().json(SuccessResponse {
        success: true,
        data: SendTokenResponse {
            program_id: ix.program_id.to_string(),
            accounts,
            instruction_data,
        },
    })
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        App::new()
            .route("/health", web::get().to(health))
            .route("/keypair", web::post().to(keypair))
            .route("/token/create", web::post().to(token_create))
            .route("/token/mint", web::post().to(token_mint))
            .route("/message/sign", web::post().to(message_sign))
            .route("/message/verify", web::post().to(message_verify))
            .route("/send/sol", web::post().to(send_sol))
            .route("/send/token", web::post().to(send_token))
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}