package top.piaopop.signer;

import android.content.Context;
import android.content.res.AssetManager;
import android.os.Environment;

import com.android.apksig.ApkSigner;
import com.android.apksig.apk.ApkFormatException;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class Signer {
    /**
     * keystore所在路径
     */
    private static String KEYSTORE_PATH = "signer.jks"; // assets 文件夹中的 jks 文件路径
    /**
     * keystore密码
     */
    private static String STORE_PASSWORD = "123456";
    /**
     * keystore别名
     */
    private static String KEY_ALIAS = "yfxbq";
    /**
     * keystore别名密码
     */
    private static String KEY_PASSWORD = "123456";
    /**
     * 签名apk路径
     */
    private static String APK_PATH = Environment.getExternalStorageDirectory() + "/签名程序/未签名.apk";
    /**
     * 签名完成输出apk路径
     */
    private static String NEW_APK_PATH = Environment.getExternalStorageDirectory() + "/签名程序/已签名.apk";


    private Context context;

    /**
     * 构造方法传入数据
     */

    public Signer(Context context) {
        this.context = context;
    }

    public void sign() throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException, UnrecoverableKeyException, ApkFormatException, SignatureException, InvalidKeyException {
        // 1.打开assets中的jks文件
        AssetManager assetsManager = context.getAssets();
        InputStream open = assetsManager.open(KEYSTORE_PATH);
        byte[] keyStoreBytes = readFully(open);

        // 2.创建 KeyStore 实例 --- 这里不能写JKS,需要写PKCS12，真的是大坑！
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(new ByteArrayInputStream(keyStoreBytes), STORE_PASSWORD.toCharArray());

        // 3.获取证书
        Certificate certificate = keyStore.getCertificate(KEY_ALIAS);
        X509Certificate x509Cert = (X509Certificate) certificate;
        List<X509Certificate> x509CertList = new ArrayList<>();
        x509CertList.add(x509Cert);

        // 4.获取私钥
        Key key = keyStore.getKey(KEY_ALIAS, KEY_PASSWORD.toCharArray());
        PrivateKey privateKey = (PrivateKey) key;

        // 5.创建SignerConfig
        List<ApkSigner.SignerConfig> signerConfigList = new ArrayList<>();
        ApkSigner.SignerConfig signerConfig = new ApkSigner.SignerConfig.Builder("易分享", privateKey, x509CertList).build();
        signerConfigList.add(signerConfig);
        new ApkSigner.Builder(signerConfigList)
                .setInputApk(new File(APK_PATH))
                .setOutputApk(new File(NEW_APK_PATH))
                .setCreatedBy("by 林子风")
                .setMinSdkVersion(24)
                .build()
                .sign();

    }

    private static byte[] readFully(InputStream in) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int n = 0;
        while (-1 != (n = in.read(buffer))) {
            out.write(buffer, 0, n);
        }
        return out.toByteArray();
    }
}
