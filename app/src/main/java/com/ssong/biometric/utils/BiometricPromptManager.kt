package com.ssong.biometric.utils

import android.content.Context
import android.content.SharedPreferences
import android.os.Build
import android.preference.PreferenceManager
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import androidx.annotation.RequiresApi
import androidx.biometric.BiometricConstants
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.core.content.edit
import androidx.fragment.app.FragmentActivity
import com.ssong.biometric.R
import java.security.InvalidAlgorithmParameterException
import java.security.Key
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class BiometricPromptManager(
    private val context: Context,
    private val title: String,
    private val subTitle: String,
    private val description: String
) {

    companion object {
        private const val TAG = "BiometricPromptManager"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val KEY_NAME = "KBIZ_YELLOW_BIOMETRIC_KEY" // MY KEY NAME
        private const val DATA_ENCRYPTED = "DATA_ENCRYPTED"
        private const val INITIALIZATION_VECTOR = "INITIALIZATION_VECTOR"
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
        private fun keyTransformation() =
            listOf(ALGORITHM, BLOCK_MODE, PADDING).joinToString(separator = "/")
    }

    private val sharedPreferences: SharedPreferences =
        PreferenceManager.getDefaultSharedPreferences(context)

    private val keyStore: KeyStore = KeyStore.getInstance(KEYSTORE).apply { load(null) }

    @RequiresApi(Build.VERSION_CODES.M)
    fun encryptPrompt(
        data: ByteArray,
        failedAction: (msg: String) -> Unit,
        successAction: (ByteArray) -> Unit
    ) {
        try {
            val secretKey = createKey()
            val cipher = getEncryptCipher(secretKey)

            handleEncrypt(cipher, data, failedAction, successAction)

        } catch (invalidAlgorithmParameterException: InvalidAlgorithmParameterException) {
            Log.e(
                TAG,
                "Encrypt BiometricPrompt InvalidAlgorithmParameterException",
                invalidAlgorithmParameterException
            )

            val msg = context.getString(R.string.BIOMETRIC_ERROR_NO_BIOMETRICS)
            failedAction(msg)

        } catch (e: Exception) {
            Log.e(TAG, "Encrypt BiometricPrompt exception", e)

            val msg = context.getString(R.string.BIOMETRIC_ERROR_DEFAULT)
            failedAction(msg)
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    fun decryptPrompt(failedAction: (msg: String) -> Unit, successAction: (ByteArray) -> Unit) {
        try {
            val secretKey = getKey()
            val initializationVector = getInitializationVector()

            if (secretKey != null && initializationVector != null) {
                val cipher = getDecryptCipher(secretKey, initializationVector)
                handleDecrypt(cipher, failedAction, successAction)
            } else {
                val msg = context.getString(R.string.BIOMETRIC_ERROR_UNREGISTERED)
                failedAction(msg)
            }

        } catch (keyPermanentlyInvalidatedException: KeyPermanentlyInvalidatedException) {
            Log.e(TAG, "Decrypt BiometricPrompt KeyPermanentlyInvalidatedException", keyPermanentlyInvalidatedException)

            val msg = context.getString(R.string.BIOMETRIC_ERROR_CHANGED)
            failedAction(msg)

        } catch (e: Exception) {
            Log.e(TAG, "Decrypt BiometricPrompt exception", e)

            val msg = context.getString(R.string.BIOMETRIC_ERROR_DEFAULT)
            failedAction(msg)
        }
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private fun createKey(): SecretKey {
        val keyGenerator = KeyGenerator.getInstance(ALGORITHM, KEYSTORE)
        val keyGenParameterSpec =
            KeyGenParameterSpec.Builder(
                KEY_NAME,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setBlockModes(BLOCK_MODE)
                .setEncryptionPaddings(PADDING)
                .setUserAuthenticationRequired(true)
                .build()

        keyGenerator.init(keyGenParameterSpec)
        return keyGenerator.generateKey()
    }

    private fun getKey(): Key? = keyStore.getKey(KEY_NAME, null)

    private fun getInitializationVector(): ByteArray? {
        val iv = sharedPreferences.getString(INITIALIZATION_VECTOR, null)
        return when {
            iv != null -> Base64.decode(iv, Base64.DEFAULT)
            else -> null
        }
    }

    private fun getEncryptedData(): ByteArray? {
        val iv = sharedPreferences.getString(DATA_ENCRYPTED, null)
        return when {
            iv != null -> Base64.decode(iv, Base64.DEFAULT)
            else -> null
        }
    }

    private fun saveEncryptedData(dataEncrypted: ByteArray, initializationVector: ByteArray) {
        sharedPreferences.edit {
            putString(DATA_ENCRYPTED, Base64.encodeToString(dataEncrypted, Base64.DEFAULT))
            putString(
                INITIALIZATION_VECTOR,
                Base64.encodeToString(initializationVector, Base64.DEFAULT)
            )
        }
    }

    private fun getEncryptCipher(key: Key): Cipher =
        Cipher.getInstance(keyTransformation()).apply { init(Cipher.ENCRYPT_MODE, key) }

    private fun getDecryptCipher(key: Key, iv: ByteArray): Cipher =
        Cipher.getInstance(keyTransformation()).apply {
            init(
                Cipher.DECRYPT_MODE,
                key,
                IvParameterSpec(iv)
            )
        }


    private fun handleEncrypt(
        cipher: Cipher,
        data: ByteArray,
        failedAction: (msg: String) -> Unit,
        successAction: (ByteArray) -> Unit
    ) {
        val executor = Executors.newSingleThreadExecutor()
        val biometricPrompt = BiometricPrompt(
            context as FragmentActivity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    result.cryptoObject?.cipher?.let {
                        val iv = it.iv
                        val encryptedData = it.doFinal(data)
                        saveEncryptedData(encryptedData, iv)
                        context.runOnUiThread { successAction(encryptedData) }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.d(TAG, "Authentication error. $errString ($errorCode)")

                    var errorMsg = biometricErrorMsg(errorCode)

                    context.runOnUiThread { failedAction(errorMsg) }
                }
            })

        val promptInfo = biometricPromptInfo()
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    private fun handleDecrypt(
        cipher: Cipher,
        failedAction: (msg: String) -> Unit,
        successAction: (ByteArray) -> Unit
    ) {
        val executor = Executors.newSingleThreadExecutor()
        val biometricPrompt = BiometricPrompt(
            context as FragmentActivity,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    result.cryptoObject?.cipher?.let {
                        val encrypted = getEncryptedData()
                        val data = it.doFinal(encrypted)
                        context.runOnUiThread { successAction(data) }
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    Log.d(TAG, "Authentication error. $errString ($errorCode)")

                    var errorMsg = biometricErrorMsg(errorCode)

                    context.runOnUiThread { failedAction(errorMsg) }
                }
            })

        val promptInfo = biometricPromptInfo()
        biometricPrompt.authenticate(promptInfo, BiometricPrompt.CryptoObject(cipher))
    }

    private fun biometricPromptInfo(): BiometricPrompt.PromptInfo {
        return BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subTitle)
            .setDescription(description)
            .setNegativeButtonText(context.getString(android.R.string.cancel))
            .build()
    }

    private fun biometricErrorMsg(errorCode: Int) = when (errorCode) {
        BiometricConstants.ERROR_HW_NOT_PRESENT -> {
            context.getString(R.string.BIOMETRIC_ERROR_HW_NOT_PRESENT)
        }

        BiometricConstants.ERROR_HW_UNAVAILABLE -> {
            context.getString(R.string.BIOMETRIC_ERROR_HW_UNAVAILABLE)
        }

        BiometricConstants.ERROR_LOCKOUT -> {
            context.getString(R.string.BIOMETRIC_ERROR_LOCKOUT)
        }

        BiometricConstants.ERROR_LOCKOUT_PERMANENT -> {
            context.getString(R.string.BIOMETRIC_ERROR_LOCKOUT_PERMANENT)
        }

        BiometricConstants.ERROR_NO_BIOMETRICS -> {
            context.getString(R.string.BIOMETRIC_ERROR_NO_BIOMETRICS)
        }

        BiometricConstants.ERROR_NO_DEVICE_CREDENTIAL -> {
            context.getString(R.string.BIOMETRIC_ERROR_NO_DEVICE_CREDENTIAL)
        }

        else -> {
            context.getString(R.string.BIOMETRIC_ERROR_DEFAULT)
        }
    }
}