package com.example.secureapp

import android.os.Bundle
import android.widget.*
import androidx.appcompat.app.AppCompatActivity
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKeys
import okhttp3.*
import java.io.File

class MainActivity : AppCompatActivity() {

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val layout = LinearLayout(this)
        layout.orientation = LinearLayout.VERTICAL

        val inputNome = EditText(this)
        inputNome.hint = "Digite seu nome"

        val inputRA = EditText(this)
        inputRA.hint = "Digite seu RA"

        val btnSave = Button(this)
        btnSave.text = "Salvar"

        val btnLoad = Button(this)
        btnLoad.text = "Recuperar"

        val btnApi = Button(this)
        btnApi.text = "Requisição SSL Pinning"

        val result = TextView(this)

        layout.addView(inputNome)
        layout.addView(inputRA)
        layout.addView(btnSave)
        layout.addView(btnLoad)
        layout.addView(btnApi)
        layout.addView(result)

        setContentView(layout)

        val masterKeyAlias = MasterKeys.getOrCreate(MasterKeys.AES256_GCM_SPEC)

        val prefs = EncryptedSharedPreferences.create(
            "secure_prefs",
            masterKeyAlias,
            applicationContext,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )

        btnSave.setOnClickListener {
            val nome = inputNome.text.toString()
            val ra = inputRA.text.toString()

            prefs.edit()
                .putString("nome", nome)
                .putString("ra", ra)
                .apply()

            Toast.makeText(this, "Dados salvos com segurança!", Toast.LENGTH_SHORT).show()
        }

        btnLoad.setOnClickListener {
            val nome = prefs.getString("nome", "N/A")
            val ra = prefs.getString("ra", "N/A")

            result.text = "Nome: $nome\nRA: $ra"
        }

        btnApi.setOnClickListener {
            callApi(result)
        }

        if (isRooted()) {
            Toast.makeText(this, "ROOT detectado!", Toast.LENGTH_LONG).show()
        }
    }

    private fun isRooted(): Boolean {
        val buildTags = android.os.Build.TAGS
        if (buildTags != null && buildTags.contains("test-keys")) {
            return true
        }

        val paths = arrayOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/system/app/Superuser.apk"
        )

        for (path in paths) {
            if (File(path).exists()) return true
        }

        return false
    }

    private fun callApi(result: TextView) {
        val hostname = "jsonplaceholder.typicode.com"

        val certificatePinner = CertificatePinner.Builder()
            .add("jsonplaceholder.typicode.com", "sha256/e89QAFJvkB7Tn3QGfsNheN8fgTxZgLECjap1xSq628w1=")
            .build()

        val client = OkHttpClient.Builder()
            .certificatePinner(certificatePinner)
            .build()

        val request = Request.Builder()
            .url("https://jsonplaceholder.typicode.com")
            .build()

        Thread {
            try {
                val response = client.newCall(request).execute()

                runOnUiThread {
                    result.text = "Sucesso: ${response.code}"
                }

            } catch (e: Exception) {

                runOnUiThread {
                    result.text = "Erro SSL Pinning bloqueou conexão!"
                }

                e.printStackTrace()
            }
        }.start()
    }
}
