package com.example.jwt.asym;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;

@SpringBootApplication
public class JwtAsymmetricApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtAsymmetricApplication.class, args);
	}

	public String createJwt(Key privateKey, int expirationSeconds, Map<String, Object> claims, String subject) throws InvalidKeyException {
		Instant now = Instant.now();
		JwtBuilder jwtBuilder = Jwts.builder();
		if (null != claims) {
			jwtBuilder.addClaims(claims);
		}
		if (null != subject) {
			jwtBuilder.setSubject(subject);
		}
		return jwtBuilder.setId(UUID.randomUUID().toString()).setIssuedAt(Date.from(now))
				.setExpiration(Date.from(now.plus(expirationSeconds, ChronoUnit.SECONDS)))
				.signWith(privateKey, SignatureAlgorithm.RS512).compact();
	}

	public PrivateKey getPrivateKey(String rsaPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(rsaPrivateKey));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(keySpec);
	}

	public Jws<Claims> parseJwt(Key publicKey, String jwtString) throws ExpiredJwtException, UnsupportedJwtException,
			MalformedJwtException, SignatureException, IllegalArgumentException {
		return Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(jwtString);
	}

	public PublicKey getPublicKey(String rsaPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(rsaPublicKey));
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(keySpec);
	}

}
