package com.dima.fooddelivery.common.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * Ключ подписи токенов.
 *
 * <p><b>Почему RS256, а не HS256, как раньше.</b> С симметричным ключом каждый, кто умеет
 * проверить токен, умеет его и выпустить: секрет один на всех. Пока токены проверял один
 * монолит, это было терпимо. Теперь их проверяют четыре сервиса, и утечка секрета из любого
 * из них — это возможность выпустить себе токен администратора. С RSA закрытый ключ есть
 * только здесь, остальные получают открытый через JWKS и подделать токен не могут.
 *
 * <p>Открытый ключ не хранится отдельно, а выводится из закрытого: в PKCS#8 у RSA лежат
 * модуль и открытая экспонента. Так нельзя ошибиться и подложить открытый ключ от другой пары —
 * а такая ошибка выглядела бы как «все токены вдруг невалидны» без единой подсказки почему.
 */
@Component
public class JwtKeys {

    /** Меньше 2048 бит RSA не считается стойким, и Nimbus такой ключ отвергнет сам. */
    static final int MIN_KEY_SIZE_BITS = 2048;

    private final RSAKey rsaKey;

    public JwtKeys(JwtProperties properties) {
        this.rsaKey = load(properties.privateKey(), properties.keyId());
    }

    /** Пара целиком: закрытая часть нужна для подписи. Наружу не отдаётся. */
    public RSAKey signingKey() {
        return rsaKey;
    }

    public RSAPublicKey publicKey() {
        try {
            return rsaKey.toRSAPublicKey();
        } catch (com.nimbusds.jose.JOSEException exception) {
            throw new IllegalStateException("Не удалось получить открытый ключ", exception);
        }
    }

    /**
     * JWKS — только открытые части. {@code toPublicJWKSet} отбрасывает закрытую экспоненту
     * и множители: опубликовать по ошибке закрытый ключ через этот метод невозможно.
     */
    public JWKSet publicJwkSet() {
        return new JWKSet(rsaKey).toPublicJWKSet();
    }

    private static RSAKey load(String base64Pkcs8, String keyId) {
        if (base64Pkcs8 == null || base64Pkcs8.isBlank()) {
            throw new IllegalStateException(
                    "JWT_PRIVATE_KEY не задан. Сгенерируйте ключ командой из README: "
                            + "openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 "
                            + "| openssl pkcs8 -topk8 -nocrypt -outform DER | base64 -w0"
            );
        }

        if (keyId == null || keyId.isBlank()) {
            throw new IllegalStateException("JWT_KEY_ID не задан: проверяющие ищут ключ в JWKS по нему");
        }

        try {
            byte[] der = Base64.getDecoder().decode(base64Pkcs8.trim());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            if (!(keyFactory.generatePrivate(new PKCS8EncodedKeySpec(der)) instanceof RSAPrivateCrtKey privateKey)) {
                throw new IllegalStateException("JWT_PRIVATE_KEY должен быть RSA-ключом в формате PKCS#8 с CRT-параметрами");
            }

            BigInteger modulus = privateKey.getModulus();

            if (modulus.bitLength() < MIN_KEY_SIZE_BITS) {
                throw new IllegalStateException(
                        "JWT_PRIVATE_KEY короче " + MIN_KEY_SIZE_BITS + " бит: такой RSA-ключ не считается стойким"
                );
            }

            RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(
                    new RSAPublicKeySpec(modulus, privateKey.getPublicExponent())
            );

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keyId)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .build();
        } catch (IllegalArgumentException | GeneralSecurityException exception) {
            throw new IllegalStateException(
                    "JWT_PRIVATE_KEY не разобран: ожидается PKCS#8 DER в Base64 одной строкой", exception
            );
        }
    }
}
