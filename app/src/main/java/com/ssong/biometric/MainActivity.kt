package com.ssong.biometric

import android.os.Build
import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Toast
import com.ssong.biometric.utils.BiometricPromptManager
import kotlinx.android.synthetic.main.activity_main.*

class MainActivity : AppCompatActivity() {

    private lateinit var biometricPromptManager: BiometricPromptManager

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        biometricPromptManager = BiometricPromptManager(this, "타이틀", "서브타이틀", "디스크립션")

        val secureText = "ssong"

        btn_encrypt.setOnClickListener {
            if (Build.VERSION.SDK_INT >= 23) {
                biometricPromptManager.encryptPrompt(
                    data = secureText.toByteArray(),
                    failedAction = { showToast(it) },
                    successAction = {
                        tv_secure.text = String(it)
                        showToast("encrypt success")
                    }
                )
            }
        }

        btn_decrypt.setOnClickListener {
            if (Build.VERSION.SDK_INT >= 23) {
                biometricPromptManager.decryptPrompt(
                    failedAction = { showToast(it) },
                    successAction = {
                        tv_secure.text = String(it)
                        showToast("decrypt success")
                    }
                )
            }
        }
    }

    private fun showToast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }
}
