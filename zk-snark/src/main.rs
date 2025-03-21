use ark_bls12_381::{Bls12_381, Fq, Fr as ScalarField, G1Affine};
use ark_ec::{
    pairing::Pairing,
    CurveGroup,
    AffineRepr,
    scalar_mul::variable_base::VariableBaseMSM
};
use ark_ff::{Field, PrimeField, UniformRand};
use ark_groth16::{Groth16, ProvingKey, VerifyingKey};
use ark_r1cs_std::{prelude::*, fields::fp::FpVar};
use ark_relations::{
    lc,
    r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError},
};
use ark_snark::SNARK;
use ark_std::{
    rand::{rngs::StdRng, SeedableRng},
    One,
};

// 身份验证电路定义
#[derive(Clone)]
struct AuthCircuit {
    secret: Option<ScalarField>,
    pubkey: Option<G1Affine>,
}

impl ConstraintSynthesizer<ScalarField> for AuthCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ScalarField>,
    ) -> Result<(), SynthesisError> {
        // 声明秘密变量
        let secret_var = FpVar::new_witness(cs.clone(), || {
            self.secret.ok_or(SynthesisError::AssignmentMissing)
        })?;
        fn fq_to_fr(fq: Fq) -> ScalarField {
            ScalarField::from(fq.into_bigint())
        }
        // 修正公钥输入变量的转换
        let pubkey_var = FpVar::new_input(cs.clone(), || {
            let fq_value = self.pubkey.ok_or(SynthesisError::AssignmentMissing)?.x();
            fq_value.map(fq_to_fr).ok_or(SynthesisError::AssignmentMissing)
        })?;

        // 获取生成器坐标（转换到电路标量场类型）
        let generator = Bls12_381::G1Affine::generator();
        let generator_x = fq_to_fr(generator.x().unwrap());
        let generator_x_var = FpVar::new_constant(cs, generator_x)?;

        // 约束：secret * G.x == pubkey.x
        (secret_var * generator_x_var).enforce_equal(&pubkey_var)?;

        Ok(())
    }
}


// 用户凭证结构
struct UserCredential {
    secret: ScalarField,
    pubkey: G1Affine,
}

impl UserCredential {
    fn new(rng: &mut impl rand::RngCore) -> Self {
        let secret = ScalarField::rand(rng);
        let pubkey = Bls12_381::G1Affine::generator()
            .mul_bigint(secret.into_bigint())
            .into_affine();
        Self { secret, pubkey }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = StdRng::seed_from_u64(2023);

    // 1. 用户注册
    let user = UserCredential::new(&mut rng);
    println!("Public Key: {:?}", user.pubkey);

    // 2. 可信设置
    let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
        AuthCircuit {
            secret: None,
            pubkey: Some(user.pubkey),
        },
        &mut rng,
    )?;

    // 3. 生成证明
    let proof = Groth16::prove(
        &pk,
        AuthCircuit {
            secret: Some(user.secret),
            pubkey: Some(user.pubkey),
        },
        &mut rng,
    )?;

    // 4. 准备公开输入（将 Fq 转换为 Fr）
    let public_input: Vec<ScalarField> = vec![fq_to_fr(user.pubkey.x().unwrap())];

    // 5. 验证证明
    let verified = Groth16::verify(&vk, &public_input, &proof)?;
    println!("Verification Result: {}", verified);

    Ok(())
}

fn fq_to_fr(fq: Fq) -> ScalarField {
    ScalarField::from(fq.into_bigint())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_proof() {
        let mut rng = ark_std::test_rng();
        let user = UserCredential::new(&mut rng);

        let (pk, vk) = Groth16::<Bls12_381>::circuit_specific_setup(
            AuthCircuit {
                secret: None,
                pubkey: Some(user.pubkey),
            },
            &mut rng,
        ).unwrap();

        let proof = Groth16::prove(
            &pk,
            AuthCircuit {
                secret: Some(user.secret),
                pubkey: Some(user.pubkey),
            },
            &mut rng,
        ).unwrap();

        // 修正的公开输入
        let public_input: Vec<ScalarField> = vec![fq_to_fr(user.pubkey.x().unwrap())];

        // 验证通过
        assert!(Groth16::verify(&vk, &public_input[..], &proof).unwrap());
    }

    fn fq_to_fr(fq: Fq) -> ScalarField {
        ScalarField::from(fq.into_bigint())
    }
}