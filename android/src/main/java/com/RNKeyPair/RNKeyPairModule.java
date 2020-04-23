package com.RNKeyPair;

import android.util.Base64;

import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.Callback;
import com.facebook.react.bridge.WritableNativeMap;

import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1Primitive;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.util.io.pem.PemObject;
import org.spongycastle.util.io.pem.PemWriter;

import java.io.IOException;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class RNKeyPairModule extends ReactContextBaseJavaModule {

    private final ReactApplicationContext reactContext;

    public RNKeyPairModule(ReactApplicationContext reactContext) {
        super(reactContext);
        this.reactContext = reactContext;
    }

    @Override
    public String getName() {
        return "RNKeyPair";
    }

    public static String getPrivateKeyPKCS8String(byte[] priv) throws GeneralSecurityException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair keyPair = kpg.genKeyPair();
        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        PrivateKeyInfo pkInfo = PrivateKeyInfo.getInstance(priv);
        ASN1Encodable encodeable = null;
        try {
            encodeable = pkInfo.parsePrivateKey();
        } catch (IOException e) {


        }
        ASN1Primitive primitive2 = encodeable.toASN1Primitive();
        byte[] privateKeyPKCS1 = new byte[0];
        try {
            privateKeyPKCS1 = primitive2.getEncoded();
        } catch (IOException e) {
            e.printStackTrace();
        }

        PemObject pemObject2 = new PemObject("RSA PRIVATE KEY", privateKeyPKCS1);
        StringWriter stringWriter2 = new StringWriter();
        PemWriter pemWriter2 = new PemWriter(stringWriter2);
        try {
            pemWriter2.writeObject(pemObject2);
            pemWriter2.close();

        } catch (IOException e) {
            e.printStackTrace();
        }
        return stringWriter2.toString();
    }


    public static String getPublicKeyX509String(PublicKey publ) throws GeneralSecurityException {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec spec = fact.getKeySpec(publ,
                X509EncodedKeySpec.class);
        return "-----BEGIN PUBLIC KEY-----\n" +
                new String(Base64.encode(spec.getEncoded(), 0)) +
                "-----END PUBLIC KEY-----";
    }

    @ReactMethod
    public void generate(Callback callback)  {
        WritableNativeMap keys = new WritableNativeMap();

        try {

            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair keyPair = kpg.genKeyPair();
            byte[] publicKey = keyPair.getPublic().getEncoded();
            byte[] privateKey = keyPair.getPrivate().getEncoded();

            KeyFactory kf = KeyFactory.getInstance("RSA");
            PublicKey publicKeyX509 = kf.generatePublic(new X509EncodedKeySpec(publicKey));
            PrivateKey privateKeyPKCS8 = kf.generatePrivate(new PKCS8EncodedKeySpec(privateKey));

            keys.putString("public", getPublicKeyX509String(publicKeyX509));
            keys.putString("private", getPrivateKeyPKCS8String(privateKey));
        }
        catch(GeneralSecurityException e) { }
        callback.invoke(keys);
    }
}

