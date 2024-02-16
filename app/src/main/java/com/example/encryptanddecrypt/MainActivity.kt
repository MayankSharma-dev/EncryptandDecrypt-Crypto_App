package com.example.encryptanddecrypt

import androidx.appcompat.app.AppCompatActivity
import android.os.Bundle
import android.widget.Toast
import com.example.encryptanddecrypt.databinding.ActivityMainBinding
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream

class MainActivity : AppCompatActivity() {

    private lateinit var binding: ActivityMainBinding
    private val cryptoManager = CryptoManager()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)

        binding.apply {
            encryptButton.setOnClickListener {
                val text = encryptField.editText?.text.toString()
                if(text.isNotEmpty()){
                    val bytes = text.encodeToByteArray()
                    val file = File(filesDir,"secrets.txt")
                    if(!file.exists()){
                        file.createNewFile()
                    }
                    val fos = FileOutputStream(file)

                    val encryptedText = cryptoManager.encrypt(bytes, fos).decodeToString()
                    encryptedString.text = encryptedText
                }else{
                    Toast.makeText(this@MainActivity,"Empty String.",Toast.LENGTH_SHORT).show()
                }
            }

            decryptButton.setOnClickListener {
                val file = File(filesDir,"secrets.txt")
                val decryptedText = cryptoManager.decrypt(FileInputStream(file)).decodeToString()
                decryptedString.text = decryptedText
            }
        }

    }
}