use actix_files::Files;
use actix_web::{App, HttpServer, Responder, get, post, web, HttpResponse};
use std::io;
use serde::Deserialize;
use rand::SeedableRng;
use rand::rngs::StdRng;
use rand::thread_rng; // 添加线程随机数生成器导入
use ark_bls12_381::Fr;
use ark_ff::{PrimeField, BigInteger}; // 增加 BigInteger 导入
use std::sync::Mutex;
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::Serialize;

// 声明func.rs作为模块
mod func;
use func::{UserCredential, MERKLE_TREE, pubkey_to_bytes};

// 交易记录数据结构
#[derive(Clone, Debug, Serialize)]
struct Transaction {
    pid: String,
    sender: String,
    recipient: String,
    amount: u64,
    timestamp: u64,
}

// 全局存储交易记录
lazy_static::lazy_static! {
    static ref TRANSACTIONS: Mutex<HashMap<String, Transaction>> = Mutex::new(HashMap::new());
    static ref BLACKLIST: Mutex<HashMap<String, bool>> = Mutex::new(HashMap::new());
    static ref ADMIN_KEY: Mutex<String> = Mutex::new(String::new());
}

// 初始化管理员密钥
fn init_admin_key() -> String {
    let mut rng = thread_rng();
    let admin = UserCredential::new(&mut rng, Fr::from(1000000u64), false);
    let admin_key = hex::encode(admin.secret.into_bigint().to_bytes_le());
    
    // 保存管理员密钥
    let mut admin_key_store = ADMIN_KEY.lock().unwrap();
    *admin_key_store = admin_key.clone();
    
    println!("管理员密钥已初始化: {}", admin_key);
    admin_key
}

// 生成唯一的PID
fn generate_unique_pid(pubkey: &str, amount: u64, recipient: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    
    let mut hasher = blake3::Hasher::new();
    hasher.update(pubkey.as_bytes());
    hasher.update(&amount.to_le_bytes());
    hasher.update(recipient.as_bytes());
    hasher.update(&timestamp.to_le_bytes());
    
    format!("tx_{}", hex::encode(&hasher.finalize().as_bytes()[0..16]))
}

#[derive(Deserialize)]
struct RegisterRequest {
    authCredential: String,
}

#[derive(Deserialize)]
struct TransferRequest {
    privateKey: String,
    amount: u64,
    recipient: String,
}

#[derive(Deserialize)]
struct AdminRequest {
    adminKey: String,
    targetAddress: String,
}

#[derive(Deserialize)]
struct PubkeyRequest {
    privateKey: String,
}

#[post("/register")]
async fn register(_req: web::Json<RegisterRequest>) -> impl Responder {
    let mut rng = thread_rng(); 
    let user = UserCredential::new(&mut rng, Fr::from(1000u64), false);
    
    // 将用户公钥添加到Merkle树
    let pubkey_bytes = pubkey_to_bytes(&user.pubkey);
    let mut merkle_tree = MERKLE_TREE.lock().unwrap();
    merkle_tree.add_leaf(&pubkey_bytes);
    
    // 返回Merkle树根哈希和用户私钥
    let root_hash = merkle_tree.root_hash()
        .map(|h| hex::encode(&h))
        .unwrap_or_else(|| "空树".to_string());
    
    // 以十六进制格式返回私钥，便于直接复制粘贴
    let private_key_hex = hex::encode(user.secret.into_bigint().to_bytes_le());
    
    println!("用户已注册并加入Merkle树，当前根哈希: {}", root_hash);
    
    HttpResponse::Ok().json(serde_json::json!({ 
        "privateKey": private_key_hex,
        "merkleRoot": root_hash
    }))
}

#[post("/transfer")]
async fn transfer(req: web::Json<TransferRequest>) -> impl Responder {
    use ark_groth16::Groth16;
    use ark_snark::SNARK;
    use func::{AuthCircuit, fq_to_fr, generate_pid};
    use ark_ff::PrimeField;
    use ark_bls12_381::Bls12_381;

    // 将十六进制私钥转换回 Fr 格式
    let parsed_key = match hex::decode(&req.privateKey) {
        Ok(bytes) => Fr::from_le_bytes_mod_order(&bytes),
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "私钥格式无效"
            }));
        }
    };

    // 创建用户对象
    let user = func::UserCredential::from_existing_secret(parsed_key, Fr::from(1000u64), false);
    
    // 验证用户是否已注册
    let pubkey_bytes = pubkey_to_bytes(&user.pubkey);
    let merkle_tree = MERKLE_TREE.lock().unwrap();
    let is_registered = merkle_tree.is_registered(&pubkey_bytes);
    
    if !is_registered {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "用户未注册，请先注册账户"
        }));
    }
    
    // 检查用户是否被封禁
    let sender_pubkey = hex::encode(&pubkey_bytes);
    println!("检查用户是否被封禁，地址: {}", sender_pubkey);
    
    // 获取黑名单并检查
    let blacklist = BLACKLIST.lock().unwrap();
    
    // 打印当前黑名单内容，用于调试
    println!("当前黑名单内容: {:?}", blacklist.keys().collect::<Vec<_>>());
    
    if blacklist.contains_key(&sender_pubkey) && blacklist[&sender_pubkey] {
        println!("用户已被封禁，拒绝转账: {}", sender_pubkey);
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "您的账户已被封禁，无法进行转账"
        }));
    }

    // 1. 设置电路 (此示例使用临时 pk, vk，正式场景下应持久化)
    let mut rng = StdRng::seed_from_u64(2023);
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        AuthCircuit {
            secret: None,
            pubkey: Some(user.pubkey),
            pubkey_x_fr: user.pubkey_x_fr,
            balance: None,
            transfer_amount: None,
            is_blacklisted: None,
        },
        &mut rng,
    ).unwrap();

    // 2. 生成证明
    let proof = Groth16::<Bls12_381>::prove(
        &pk,
        AuthCircuit {
            secret: Some(user.secret),
            pubkey: None,
            pubkey_x_fr: user.pubkey_x_fr,
            balance: Some(user.balance),
            transfer_amount: Some(Fr::from(req.amount)),
            is_blacklisted: Some(user.is_blacklisted),
        },
        &mut rng,
    ).unwrap();

    // 3. 验证证明
    let public_input = vec![user.pubkey_x_fr.unwrap()];
    let verified = Groth16::<Bls12_381>::verify(&vk, &public_input, &proof).unwrap();

    if verified {
        // 生成唯一交易PID
        let sender_pubkey = hex::encode(pubkey_to_bytes(&user.pubkey));
        let pid = generate_unique_pid(&sender_pubkey, req.amount, &req.recipient);
        
        // 创建并存储交易记录
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
            
        let transaction = Transaction {
            pid: pid.clone(),
            sender: sender_pubkey,
            recipient: req.recipient.clone(),
            amount: req.amount,
            timestamp,
        };
        
        // 存储交易记录
        let mut transactions = TRANSACTIONS.lock().unwrap();
        transactions.insert(pid.clone(), transaction);
        
        println!("新交易已创建: PID={}, 金额={}, 接收方={}", pid, req.amount, req.recipient);
        
        return HttpResponse::Ok().json(serde_json::json!({
            "pid": pid,
            "signature": format!("zk_ok_{}", pid),
            "merkleVerified": true,
            "timestamp": timestamp
        }));
    } else {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "ZK verification failed"
        }));
    }
}

#[post("/ban")]
async fn ban_user(req: web::Json<AdminRequest>) -> impl Responder {
    // 验证管理员密钥
    let admin_key = ADMIN_KEY.lock().unwrap();
    if req.adminKey != *admin_key {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "管理员密钥无效，操作被拒绝"
        }));
    }
    
    // 将目标用户加入黑名单
    let mut blacklist = BLACKLIST.lock().unwrap();
    
    // 确保地址是有效的 hex 格式
    if !req.targetAddress.chars().all(|c| c.is_digit(16)) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "提供的地址不是有效的十六进制格式"
        }));
    }
    
    blacklist.insert(req.targetAddress.clone(), true);
    
    // 打印黑名单内容
    println!("用户已被封禁: {}", req.targetAddress);
    println!("当前黑名单: {:?}", blacklist.keys().collect::<Vec<_>>());
    
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!("用户 {} 已被封禁", req.targetAddress)
    }))
}

#[post("/unban")]
async fn unban_user(req: web::Json<AdminRequest>) -> impl Responder {
    // 验证管理员密钥
    let admin_key = ADMIN_KEY.lock().unwrap();
    if req.adminKey != *admin_key {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "管理员密钥无效，操作被拒绝"
        }));
    }
    
    // 将目标用户从黑名单移除
    let mut blacklist = BLACKLIST.lock().unwrap();
    blacklist.remove(&req.targetAddress);
    
    println!("用户已被解禁: {}", req.targetAddress);
    
    HttpResponse::Ok().json(serde_json::json!({
        "success": true,
        "message": format!("用户 {} 已被解禁", req.targetAddress)
    }))
}

#[get("/get_admin_key")]
async fn get_admin_key() -> impl Responder {
    let admin_key = {
        let key = ADMIN_KEY.lock().unwrap();
        if key.is_empty() {
            init_admin_key()
        } else {
            key.clone()
        }
    };
    
    HttpResponse::Ok().json(serde_json::json!({
        "adminKey": admin_key
    }))
}

// 添加查询交易记录的API端点
#[get("/transaction/{pid}")]
async fn get_transaction(pid: web::Path<String>) -> impl Responder {
    let transactions = TRANSACTIONS.lock().unwrap();
    let pid_str = pid.into_inner(); // 将 web::Path<String> 转换为 String
    
    println!("查询交易记录，PID: {}", pid_str);
    
    if let Some(tx) = transactions.get(&pid_str) {
        println!("交易记录已找到: {:?}", tx);
        let response = serde_json::json!({
            "pid": tx.pid,
            "sender": tx.sender.clone(),
            "recipient": tx.recipient.clone(),
            "amount": tx.amount,
            "timestamp": tx.timestamp,
            "status": "已确认",
            "block_height": tx.timestamp / 10 + 100000, // 模拟区块高度
            "confirmation_count": SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() - tx.timestamp
        });
        HttpResponse::Ok().json(response)
    } else {
        println!("找不到PID为{}的交易记录", pid_str);
        HttpResponse::NotFound().json(serde_json::json!({
            "error": "交易记录不存在",
            "pid": pid_str
        }))
    }
}

#[post("/get_pubkey")]
async fn get_pubkey(req: web::Json<PubkeyRequest>) -> impl Responder {
    // 将十六进制私钥转换回 Fr 格式
    let parsed_key = match hex::decode(&req.privateKey) {
        Ok(bytes) => Fr::from_le_bytes_mod_order(&bytes),
        Err(_) => {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "私钥格式无效"
            }));
        }
    };

    // 创建用户对象
    let user = func::UserCredential::from_existing_secret(parsed_key, Fr::from(1000u64), false);
    
    // 获取用户公钥并转换为hex格式
    let pubkey_bytes = pubkey_to_bytes(&user.pubkey);
    let pubkey_hex = hex::encode(&pubkey_bytes);
    
    HttpResponse::Ok().json(serde_json::json!({
        "pubkey": pubkey_hex
    }))
}

#[get("/send_transaction")]
async fn send_transaction() -> impl Responder {
    "Transaction sent!"
}

#[actix_web::main]
async fn main() -> io::Result<()> {
    // 初始化管理员密钥
    let admin_key = init_admin_key();
    println!("系统初始化完成，管理员密钥: {}", admin_key);
    
    // 启动服务器
    let server = HttpServer::new(|| {
        App::new()
            .service(register)
            .service(transfer)
            .service(send_transaction)
            .service(get_transaction)
            .service(ban_user)
            .service(unban_user)
            .service(get_admin_key)
            .service(get_pubkey)  // 添加获取公钥的API端点
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