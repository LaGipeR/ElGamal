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

    pub fn generate_keypair() -> (SecretKey, PublicKey) {
        let secret_key = generate_secret_key();
        let public_key = generate_public_key(&secret_key);

        (secret_key, public_key)
    }

    pub fn generate_secret_key() -> SecretKey {
        let mut gen = random_generator::RandGen::new(0);
        gen.set_seed_from_time();

        gen.next_long_int(
            &LongInt::from_blocks_big_endian(vec![1]),
            &(&p - LongInt::from_blocks_big_endian(vec![2])),
        )
    }

    pub fn generate_public_key(secret_key: &SecretKey) -> PublicKey {
        LongInt::pow(&g(), &secret_key, &p())
    }

    pub fn sing(message_hash: &LongInt, secret_key: &SecretKey) -> (LongInt, LongInt) {
        let p_minus_1 = p() - LongInt::from_blocks_big_endian(vec![1]);

        let mut gen = random_generator::RandGen::new(0);
        gen.set_seed_from_time();

        let k = loop {
            let val = gen.next_long_int(
                &LongInt::from_blocks_big_endian(vec![2]),
                &(&p - LongInt::from_blocks_big_endian(vec![2])),
            );

            if LongInt::gcd(&val, &p_minus_1) == LongInt::from_hex("1") {
                break val;
            }
        };

        let r = LongInt::pow(&g(), &k, &p());

        let s = (((&message_hash) + ((&p_minus_1) - (&secret_key) * (&r)))
            * LongInt::pow(
                &k,
                &(p() - LongInt::from_blocks_big_endian(vec![2])),
                &p_minus_1,
            ))
            % (&p_minus_1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
