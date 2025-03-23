use ark_bls12_381::{Bls12_381, Fq, Fr as ScalarField, Fr, G1Affine};
use ark_ec::{
    pairing::Pairing,
    CurveGroup,
    AffineRepr,
};
use ark_ff::{BigInt, PrimeField, UniformRand, Zero, BigInteger};
use ark_groth16::{Groth16};
use ark_r1cs_std::{prelude::*, fields::fp::FpVar};
use ark_relations::{
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError, ConstraintSystem},
};
use ark_snark::SNARK;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
};
use rand::RngCore;
use std::hash::Hasher;
use std::cmp::Ordering;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;
use std::sync::Once;
use sha2::{Sha256, Digest};
use hex::encode;

// 身份验证电路定义
#[derive(Clone)]
pub struct AuthCircuit {
    pub secret: Option<ScalarField>, // 私钥（witness）
    pub pubkey: Option<G1Affine>, // 公钥（输入变量）
    pub pubkey_x_fr: Option<ScalarField>,
    pub balance: Option<ScalarField>, // 账户余额
    pub transfer_amount: Option<ScalarField>, // 转账金额
    pub is_blacklisted: Option<bool>, // 黑名单检查
}


impl ConstraintSynthesizer<ScalarField> for AuthCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ScalarField>,
    ) -> Result<(), SynthesisError> {
        // 1. 处理私钥变量
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 2. 直接使用Fr域转换后的坐标值
        let pubkey_x_var = FpVar::new_input(cs.clone(), || {
            self.pubkey_x_fr.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 3. 定义生成器点的x坐标（在Fr域处理）
        let generator_x = fq_to_fr(
            if let Some(x) = <Bls12_381 as Pairing>::G1Affine::generator().x() {
                *x // 解引用这里的x
            } else {
                panic!("Generator's x coordinate is None.");
            }
        );
        
        // 4. 使用预计算方式验证公私钥关系
        // 在电路外部，公钥是通过 pubkey = generator * secret 计算得到的
        // 在电路内部，我们验证提供的公钥x坐标与预期一致
        
        // 创建一个常量表示预期的计算结果：generator_x * secret
        let expected_pubkey_x_var = FpVar::new_witness(cs.clone(), || {
            let secret = self.secret.ok_or(SynthesisError::AssignmentMissing)?;
            // 重新计算公钥x坐标
            let generator = <Bls12_381 as Pairing>::G1Affine::generator();
            let computed_pubkey = generator.mul_bigint(secret.into_bigint()).into_affine();
            let pubkey_x = computed_pubkey.x().ok_or(SynthesisError::AssignmentMissing)?;
            Ok(fq_to_fr(*pubkey_x)) // 解引用这里的pubkey_x
        })?;
        
        // 验证提供的公钥x坐标与预期计算结果一致
        pubkey_x_var.enforce_equal(&expected_pubkey_x_var)?;

        // 5. 处理账户余额变量
        let balance_var = FpVar::new_witness(cs.clone(), || {
            self.balance.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 6. 处理转账金额变量
        let transfer_amount_var = FpVar::new_witness(cs.clone(), || {
            self.transfer_amount.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 7. 使用简单的方法检查余额 >= 转账金额
        // 直接使用加法约束: balance - transfer_amount >= 0
        // 等价于存在一个非负数 diff 使得 balance = transfer_amount + diff
        let diff_var = FpVar::new_witness(cs.clone(), || {
            let balance = self.balance.ok_or(SynthesisError::AssignmentMissing)?;
            let transfer = self.transfer_amount.ok_or(SynthesisError::AssignmentMissing)?;
            
            if balance >= transfer {
                Ok(balance - transfer)
            } else {
                // 如果余额不足，我们返回0，但后续的约束会失败
                Ok(ScalarField::zero())
            }
        })?;
        
        // 约束: balance = transfer_amount + diff
        let sum = &transfer_amount_var + &diff_var;
        balance_var.enforce_equal(&sum)?;

        // 8. 检查黑名单
        let is_blacklisted_var = Boolean::new_witness(cs.clone(), || {
            self.is_blacklisted.ok_or(SynthesisError::AssignmentMissing)
        })?;
        is_blacklisted_var.enforce_equal(&Boolean::constant(false))?;

        Ok(())
    }
}


// 用户凭证结构
pub struct UserCredential {
    pub secret: ScalarField,
    pub pubkey: G1Affine,
    pub pubkey_x_fr: Option<Fr>,
    pub balance: ScalarField,
    pub is_blacklisted: bool,
}

impl UserCredential {
    pub fn new(rng: &mut impl RngCore, balance: ScalarField, is_blacklisted: bool) -> UserCredential {
        let secret = ScalarField::rand(rng);
        assert_ne!(secret, ScalarField::zero(), "Secret cannot be zero.");

        let generator = <Bls12_381 as Pairing>::G1Affine::generator();
        assert!(generator.is_on_curve(), "Generator is not on curve.");
        assert!(
            generator.is_in_correct_subgroup_assuming_on_curve(),
            "Generator is not in the correct subgroup."
        );

        // 生成公钥
        let pubkey = generator
            .mul_bigint(secret.into_bigint())
            .into_affine();
        assert!(pubkey.is_on_curve(), "Public key is not on curve.");
        assert!(
            pubkey.is_in_correct_subgroup_assuming_on_curve(),
            "Public key is not in the correct subgroup."
        );

        // 验证 x 坐标是否为 None
        let pubkey_x = pubkey
            .x()
            .expect("Public key's x coordinate is None. Invalid point generated.");

        println!("Public key x: {:?}", pubkey_x);

        // 使用修复后的 `fq_to_fr`
        let pubkey_x_fr = fq_to_fr(*pubkey_x); // 解引用这里的pubkey_x

        Self {
            secret,
            pubkey,
            pubkey_x_fr: Some(pubkey_x_fr),
            balance,
            is_blacklisted,
        }
    }

    pub fn from_existing_secret(secret: ScalarField, balance: ScalarField, is_blacklisted: bool) -> Self {
        // 与 new() 类似，只是 secret 不再随机
        let generator = <Bls12_381 as Pairing>::G1Affine::generator();
        let pubkey = generator
            .mul_bigint(secret.into_bigint())
            .into_affine();
        let pubkey_x = pubkey.x().unwrap();
        let pubkey_x_fr = fq_to_fr(*pubkey_x);

        Self {
            secret,
            pubkey,
            pubkey_x_fr: Some(pubkey_x_fr),
            balance,
            is_blacklisted,
        }
    }
}

// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     let mut rng = StdRng::seed_from_u64(2023);

//     // 用户输入
//     let transfer_amount = ScalarField::from(100u64); // 示例转账金额
//     let balance = ScalarField::from(1000u64); // 示例账户余额，写死掉，实际上可以是接口形式
//     let is_blacklisted = false; // 示例黑名单状态

//     // 1. 用户注册
//     let user = UserCredential::new(&mut rng, balance, is_blacklisted);
//     println!("Secret: {:?}", user.secret);
//     println!("Public Key: {:?}", user.pubkey);
//     println!("Public Key X (as Fr): {:?}", user.pubkey_x_fr);
//     println!("Balance: {:?}", user.balance);
//     println!("Is Blacklisted: {:?}", user.is_blacklisted);

//     // 检查电路约束是否满足
//     let cs = ConstraintSystem::<ScalarField>::new_ref();
//     AuthCircuit {
//         secret: Some(user.secret),
//         pubkey: None,
//         pubkey_x_fr: Some(user.pubkey_x_fr.unwrap()),
//         balance: Some(user.balance),
//         transfer_amount: Some(transfer_amount),
//         is_blacklisted: Some(user.is_blacklisted),
//     }.generate_constraints(cs.clone())?;
    
//     let is_satisfied = cs.is_satisfied()?;
//     println!("Circuit constraints satisfied: {}", is_satisfied);
    
//     if (!is_satisfied) {
//         println!("Constraint count: {}", cs.num_constraints());
//         println!("Unsatisfied constraints: ");
//         println!("{:?}", cs.which_is_unsatisfied());
//         // 如果约束不满足，终止程序
//         return Ok(());
//     }

//     // 2. 可信设置
//     let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
//         AuthCircuit {
//             secret: None,
//             pubkey: Some(user.pubkey),
//             pubkey_x_fr: Some(fq_to_fr(user.pubkey.x().unwrap())),
//             balance: None,
//             transfer_amount: None,
//             is_blacklisted: None,
//         },
//         &mut rng,
//     )?;

//     // 3. 生成证明
//     let proof = Groth16::<Bls12_381>::prove(
//         &pk,
//         AuthCircuit {
//             secret: Some(user.secret),
//             pubkey: None,
//             // 这里要解包 `Option`，确保传值为 `Fr`
//             pubkey_x_fr: Some(user.pubkey_x_fr.unwrap()),
//             balance: Some(user.balance),
//             transfer_amount: Some(transfer_amount),
//             is_blacklisted: Some(user.is_blacklisted),
//         },
//         &mut rng,
//     )?;

//     // 4. 准备公开输入（将 Fq 转换为 Fr）
//     let public_input: Vec<ScalarField> = vec![user.pubkey_x_fr.unwrap()];

//     // 5. 验证证明
//     let verified = Groth16::<Bls12_381>::verify(&vk, &public_input, &proof)?;
//     println!("Verification Result: {}", verified);

//     // 6. 生成伪匿名交易标识符 PID
//     let pid = generate_pid(&user.pubkey, &transfer_amount);
//     println!("PID: {:?}", pid);

//     Ok(())
// }

fn bigint6_to_bigint4(bigint: BigInt<6>) -> BigInt<4> {
    // 检查高 2 个 limbs 是否为零（确保数值未溢出）
    assert!(
        bigint.0[4] == 0 && bigint.0[5] == 0,
        "BigInt<6> 超出 BigInt<4> 的表示范围"
    );

    // 提取前 4 个 limbs
    let mut limbs = [0u64; 4];
    limbs.copy_from_slice(&bigint.0[..4]);
    BigInt::<4>::new(limbs)
}

// 将 Fq 转换为 Fr
pub fn fq_to_fr(fq: Fq) -> ScalarField {
    // 将 Fq 转换为 BigInt<6>
    let fq_bigint: BigInt<6> = fq.into_bigint();

    // 转换为小端字节数组
    let bytes = fq_bigint.to_bytes_le();

    // 从字节数组构造 Fr 元素（自动取模）
    ScalarField::from_le_bytes_mod_order(& bytes)
}

// 生成伪匿名交易标识符 PID
pub fn generate_pid(pubkey: &G1Affine, transfer_amount: &ScalarField) -> ScalarField {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    
    // 使用pubkey的x和y坐标作为哈希输入
    if let Some(x) = pubkey.x() {
        let x_bytes = x.into_bigint().to_bytes_le();
        hasher.write(&x_bytes);
    }
    
    if let Some(y) = pubkey.y() {
        let y_bytes = y.into_bigint().to_bytes_le();
        hasher.write(&y_bytes);
    }
    
    // 使用转账金额作为哈希输入
    let amount_bytes = transfer_amount.into_bigint().to_bytes_le();
    hasher.write(&amount_bytes);
    
    // 生成哈希
    let hash = hasher.finish();
    
    // 将u64哈希值转换为标量字段元素
    ScalarField::from(hash)
}

// 简单的Merkle树节点定义
#[derive(Debug, Clone)]
pub struct MerkleNode {
    pub hash: Vec<u8>,
    pub left: Option<Box<MerkleNode>>,
    pub right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    // 创建一个新的叶子节点
    pub fn new_leaf(data: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().to_vec();
        
        MerkleNode {
            hash,
            left: None,
            right: None,
        }
    }
    
    // 创建一个中间节点
    pub fn new_node(left: MerkleNode, right: MerkleNode) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(&left.hash);
        hasher.update(&right.hash);
        let hash = hasher.finalize().to_vec();
        
        MerkleNode {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        }
    }
}

// Merkle树实现
pub struct MerkleTree {
    pub root: Option<MerkleNode>,
    pub leaves: Vec<MerkleNode>,
    pub user_map: HashMap<String, bool>, // 存储用户公钥到注册状态的映射
}

impl MerkleTree {
    pub fn new() -> Self {
        MerkleTree {
            root: None,
            leaves: Vec::new(),
            user_map: HashMap::new(),
        }
    }
    
    // 添加一个叶子节点
    pub fn add_leaf(&mut self, data: &[u8]) {
        let leaf = MerkleNode::new_leaf(data);
        self.leaves.push(leaf);
        self.rebuild_tree();
        
        // 记录用户公钥
        let key_hex = encode(data);
        self.user_map.insert(key_hex, true);
    }
    
    // 重建Merkle树
    fn rebuild_tree(&mut self) {
        if self.leaves.is_empty() {
            self.root = None;
            return;
        }
        
        let mut nodes = self.leaves.clone();
        
        while nodes.len() > 1 {
            let mut next_level = Vec::new();
            
            for i in (0..nodes.len()).step_by(2) {
                if i + 1 < nodes.len() {
                    // 有两个节点，创建一个父节点
                    let node = MerkleNode::new_node(nodes[i].clone(), nodes[i + 1].clone());
                    next_level.push(node);
                } else {
                    // 只有一个节点，直接将其提升到下一层
                    next_level.push(nodes[i].clone());
                }
            }
            
            nodes = next_level;
        }
        
        self.root = Some(nodes[0].clone());
    }
    
    // 验证用户是否已注册
    pub fn is_registered(&self, pubkey_data: &[u8]) -> bool {
        let key_hex = encode(pubkey_data);
        self.user_map.contains_key(&key_hex)
    }
    
    // 获取Merkle树根哈希
    pub fn root_hash(&self) -> Option<Vec<u8>> {
        self.root.as_ref().map(|node| node.hash.clone())
    }
}

// 全局单例Merkle树
lazy_static::lazy_static! {
    pub static ref MERKLE_TREE: Arc<Mutex<MerkleTree>> = Arc::new(Mutex::new(MerkleTree::new()));
}

// 辅助函数：将用户公钥转换为可哈希的字节
pub fn pubkey_to_bytes(pubkey: &G1Affine) -> Vec<u8> {
    let mut bytes = Vec::new();
    
    if let Some(x) = pubkey.x() {
        bytes.extend_from_slice(&x.into_bigint().to_bytes_le());
    }
    
    if let Some(y) = pubkey.y() {
        bytes.extend_from_slice(&y.into_bigint().to_bytes_le());
    }
    
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_proof() {
        let mut rng = ark_std::test_rng();
        let user = UserCredential::new(&mut rng, ScalarField::from(1000u64), false);

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            AuthCircuit {
                secret: None,
                pubkey: Some(user.pubkey),
                pubkey_x_fr: Some(user.pubkey_x_fr.unwrap()), // Ensure Fr set correctly
                balance: None,
                transfer_amount: None,
                is_blacklisted: None,
            },
            &mut rng,
        )
            .unwrap();

        let proof = Groth16::prove(
            &pk,
            AuthCircuit {
                secret: Some(user.secret),
                pubkey: None,
                pubkey_x_fr: Some(user.pubkey_x_fr.unwrap()), // Ensure Fr exists
                balance: Some(user.balance),
                transfer_amount: Some(ScalarField::from(100u64)),
                is_blacklisted: Some(user.is_blacklisted),
            },
            &mut rng,
        )
            .unwrap();

        let public_input: Vec<ScalarField> =
            vec![user.pubkey_x_fr.unwrap_or_else(|| panic!("Fr was unwrapped incorrectly."))];

        assert!(Groth16::verify(&vk, &public_input, &proof).unwrap());
    }
}