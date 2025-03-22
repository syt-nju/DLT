// main.rs
use actix_files::Files;
use actix_web::{post, web, App, HttpResponse, HttpServer, Responder};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_instruction,
    transaction::Transaction,
};
use std::str::FromStr;  // 移除 sync::Ar
use webbrowser;
use std::sync::{Arc, Mutex}; // 添加此行

// 硬编码的私钥（测试用）
const SECRET_KEY: [u8; 64] = [
    49, 198, 91, 67, 198, 82, 177, 153, 246, 226, 18, 28, 204, 90, 168, 237, 25, 183, 195, 250, 87,
    167, 35, 97, 218, 248, 179, 196, 81, 197, 57, 184, 84, 196, 26, 124, 108, 139, 43, 223, 200,
    119, 107, 154, 160, 7, 224, 84, 58, 182, 224, 192, 105, 12, 195, 69, 110, 95, 156, 159, 209,
    200, 101, 159,
];

#[derive(serde::Deserialize)]
struct TransactionRequest {
    recipient: String,
    amount: u64,
}

#[post("/sendTransaction")]
async fn send_transaction(req: web::Json<TransactionRequest>) -> impl Responder {
    // 创建 Keypair
    let keypair = match Keypair::from_bytes(&SECRET_KEY) {
        Ok(k) => k,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("密钥错误: {}", e) })),
    };

    // 解析接收方地址
    let recipient = match Pubkey::from_str(&req.recipient) {
        Ok(p) => p,
        Err(e) => return HttpResponse::BadRequest().json(serde_json::json!({ "error": format!("无效地址: {}", e) })),
    };

    // 创建 RPC 客户端
    let rpc_url = "https://api.devnet.solana.com";
    let client = Arc::new(Mutex::new(RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed())));

    // 构建交易
    let instruction = system_instruction::transfer(
        &keypair.pubkey(),
        &recipient,
        req.amount,
    );

    let mut transaction = Transaction::new_with_payer(&[instruction], Some(&keypair.pubkey()));

    // 获取最新区块哈希
    let client_clone = Arc::clone(&client);
    let recent_blockhash = match web::block(move || client_clone.lock().unwrap().get_latest_blockhash()).await {
        Ok(Ok(b)) => b,
        Ok(Err(e)) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("获取区块哈希失败: {}", e) })),
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({ "error": "获取区块哈希失败" })),
    };

    transaction.sign(&[&keypair], recent_blockhash);

    // 发送交易
    let client_clone = Arc::clone(&client);
    match web::block(move || client_clone.lock().unwrap().send_and_confirm_transaction(&transaction)).await {
        Ok(Ok(signature)) => HttpResponse::Ok().json(serde_json::json!({
            "success": true,
            "signature": signature.to_string()
        })),
        Ok(Err(e)) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": format!("交易失败: {}", e) })),
        Err(_) => HttpResponse::InternalServerError().json(serde_json::json!({ "error": "交易失败" })),
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 启动服务器
    let server = HttpServer::new(|| {
        App::new()
            .service(send_transaction)
            .service(Files::new("/", "./public").index_file("index.html"))
    })
        .bind("127.0.0.1:3000")?;

    // 自动打开浏览器
    if let Err(e) = webbrowser::open("http://localhost:3000") {
        eprintln!("无法自动打开浏览器: {}", e);
    }

    println!("🚀 服务器运行在 http://localhost:3000");
    server.run().await
}