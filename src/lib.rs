pub mod ElGamal {
    use long_int::LongInt;

    type SecretKey = LongInt;
    type PublicKey = LongInt;

    pub fn p() -> LongInt {
        (LongInt::from_blocks_big_endian(vec![3]) << 3276)
            - LongInt::from_blocks_big_endian(vec![1])
    }

    pub fn g() -> LongInt {
        (LongInt::from_blocks_big_endian(vec![3]) << 1274)
            - LongInt::from_blocks_big_endian(vec![1])
    }

    pub fn random_long_int() -> LongInt {
        let mut gen = random_generator::RandGen::new(0);
        gen.set_seed_from_time();

        gen.next_long_int(
            &LongInt::from_blocks_big_endian(vec![1]),
            &(&p() - LongInt::from_blocks_big_endian(vec![2])),
        )
    }

    pub fn generate_keypair() -> (SecretKey, PublicKey) {
        let secret_key = generate_secret_key();
        let public_key = generate_public_key(&secret_key);

        (secret_key, public_key)
    }

    pub fn generate_secret_key() -> SecretKey {
        random_long_int()
    }

    pub fn generate_public_key(secret_key: &SecretKey) -> PublicKey {
        LongInt::pow(&g(), &secret_key, &p())
    }

    pub fn sign(message_hash: &LongInt, secret_key: &SecretKey) -> (LongInt, LongInt) {
        let p_minus_1 = p() - LongInt::from_blocks_big_endian(vec![1]);

        let k = loop {
            let val = random_long_int();

            if LongInt::gcd(&val, &p_minus_1) == LongInt::from_hex("1") {
                break val;
            }
        };

        let r = LongInt::pow(&g(), &k, &p());

        let s = ((message_hash + (&p_minus_1 - (secret_key * &r) % &p_minus_1))
            * inv(&k, &p_minus_1))
            % &p_minus_1;

        return if &s == &LongInt::new() {
            sign(message_hash, secret_key)
        } else {
            (r, s)
        };
    }

    pub fn verify(
        sign: &(LongInt, LongInt),
        message_hash: &LongInt,
        public_key: &PublicKey,
    ) -> bool {
        let (r, s) = sign;

        let p = p();
        let p_minus_1 = &p - LongInt::from_hex("1");

        if !(&LongInt::new() < r && r < &p) {
            return false;
        }
        if !(&LongInt::new() < s && s < &p_minus_1) {
            return false;
        }

        LongInt::pow(&g(), message_hash, &p)
            == (LongInt::pow(&public_key, r, &p) * LongInt::pow(r, s, &p)) % &p
    }

    pub fn encrypt(message: &LongInt, public_key: &PublicKey) -> Vec<(LongInt, LongInt)> {
        let mut message = message.clone();
        let zero = LongInt::new();
        let p = p();
        let mut result = Vec::new();
        while &message != &zero {
            result.push(encrypt_block(&(&message % &p), public_key));
            message = message / &p;
        }

        result.reverse();
        result
    }

    fn encrypt_block(message_block: &LongInt, public_key: &PublicKey) -> (LongInt, LongInt) {
        let k = random_long_int();
        let p = p();
        let x = LongInt::pow(&g(), &k, &p);
        let y = (LongInt::pow(public_key, &k, &p) * message_block) % &p;

        (x, y)
    }

    pub fn decrypt(ciphertext: &Vec<(LongInt, LongInt)>, secret_key: &SecretKey) -> LongInt {
        let mut message = LongInt::new();
        let p = p();
        for ct in ciphertext {
            message = message * &p + decrypt_block(ct, secret_key);
        }

        message
    }

    fn decrypt_block(ciphertext: &(LongInt, LongInt), secret_key: &SecretKey) -> LongInt {
        let (x, y) = ciphertext;

        let p = p();
        let s = LongInt::pow(x, secret_key, &p);
        let message = (y * LongInt::pow(&s, &(&p - &LongInt::from_hex("2")), &p)) % &p;

        message
    }

    pub fn inv(num: &LongInt, module: &LongInt) -> LongInt {
        let zero = LongInt::new();
        let mut x = LongInt::new();
        let mut y = LongInt::from_hex("1");
        let mut u = LongInt::from_hex("1");
        let mut v = LongInt::new();

        let mut a = num.clone();
        let mut b = module.clone();

        while &a != &zero {
            let q = &b / &a;
            let r = &b % &a;
            let m = (&x + (module - (&u * &q) % module)) % module;
            let n = (&y + (module - (&v * &q) % module)) % module;

            b = a;
            a = r;
            x = u;
            y = v;
            u = m;
            v = n;
        }

        if b == LongInt::from_hex("1") {
            return x % module;
        } else {
            panic!("");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::ElGamal::*;
    use long_int::*;
    use random_generator::RandGen;
    use std::fmt::Write;

    #[test]
    fn test_inv() {
        let module = LongInt::from_blocks_big_endian(vec![10]);
        let a = LongInt::from_blocks_big_endian(vec![3]);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");

        let module = LongInt::from_blocks_big_endian(vec![10]);
        let a = LongInt::from_blocks_big_endian(vec![7]);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");

        let module = LongInt::from_blocks_big_endian(vec![10]);
        let a = LongInt::from_blocks_big_endian(vec![1]);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");

        let module = LongInt::from_blocks_big_endian(vec![17]);
        let a = LongInt::from_blocks_big_endian(vec![91]);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");

        let module = LongInt::from_blocks_big_endian(vec![17]);
        let a = LongInt::from_blocks_big_endian(vec![14]);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");

        let module = LongInt::from_blocks_big_endian(vec![17]);
        let a = LongInt::from_blocks_big_endian(vec![9]);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");

        let module = (LongInt::from_blocks_big_endian(vec![141]) << 141) + LongInt::from_hex("1");
        let a = LongInt::from_blocks_big_endian(vec![9]);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");

        let module = (LongInt::from_blocks_big_endian(vec![141]) << 141) + LongInt::from_hex("1");
        let a = LongInt::from_blocks_big_endian(vec![9]);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");

        let module = (LongInt::from_blocks_big_endian(vec![141]) << 141) + LongInt::from_hex("1");
        let a = LongInt::from_blocks_big_endian(vec![9]);
        let a = inv(&a, &module);
        let inv_a = inv(&a, &module);
        assert_eq!(((a * inv_a) % module).getHex(), "1");
    }

    const N: usize = 1_000 as usize;

    #[ignore]
    #[test]
    fn test_inv_prime_many() {
        let module = (LongInt::from_blocks_big_endian(vec![141]) << 141) + LongInt::from_hex("1");
        let mut gen = RandGen::new(0);
        gen.set_seed_from_time();

        for _ in 0..N {
            let a = gen.next_long_int(&LongInt::from_hex("1"), &module);
            let inv_a = inv(&a, &module);
            assert_eq!(((a * inv_a) % &module).getHex(), "1");
        }
    }

    #[ignore]
    #[test]
    fn test_inv_not_prime_many() {
        let module = LongInt::from_blocks_big_endian(vec![141]) << 141;
        let mut gen = RandGen::new(0);
        gen.set_seed_from_time();

        for _ in 0..N {
            let a = loop {
                let val = gen.next_long_int(&LongInt::from_hex("1"), &module);
                if LongInt::gcd(&val, &module) == LongInt::from_hex("1") {
                    break val;
                }
            };

            let inv_a = inv(&a, &module);
            assert_eq!(((a * inv_a) % &module).getHex(), "1");
        }
    }

    fn message2long_int(message: &str) -> LongInt {
        let mut hex_m = String::new();
        for &byte in message.as_bytes() {
            hex_m.push_str(&format!("{:x}", byte));
        }
        LongInt::from_hex(&hex_m)
    }

    #[test]
    fn test_sign() {
        let mut hasher = sha1::SHA1::new();
        let (secret_key, public_key) = generate_keypair();

        let m = "hello world!";
        let long_int_m = message2long_int(m);

        hasher.add(&sha1::u8_slice_to_bool(&m.as_bytes()));
        let hash = hasher.finalize();

        let sign = sign(&hash, &secret_key);

        assert_eq!(verify(&sign, &hash, &public_key), true);
    }

    #[test]
    fn test_encrypt() {
        let (secret_key, public_key) = generate_keypair();

        let m = "hello world!";
        let long_int_m = message2long_int(m);

        let c = encrypt(&long_int_m, &public_key);

        let decrypt_message = decrypt(&c, &secret_key);

        assert_eq!(long_int_m.getHex(), decrypt_message.getHex());
    }
}
