package com.example.encryptanddecrypt

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.IvParameterSpec

class CryptoManager {

    //instance KeyStore
    private val keyStore = KeyStore.getInstance("AndroidKeyStore").apply {
        load(null)
    }

    //cipher for encryption
    private val encryptCipher get() = Cipher.getInstance(TRANSFORMATION).apply {
        init(Cipher.ENCRYPT_MODE,getKey())
    }

    private fun getDecryptCipherForIV(iv:ByteArray): Cipher{
        return Cipher.getInstance(TRANSFORMATION).apply {
            init(Cipher.DECRYPT_MODE, getKey(), IvParameterSpec(iv))
        }
    }

    // checking existing key
    private fun getKey(): SecretKey {
        val existingKey = keyStore.getEntry(ALIAS,null) as? KeyStore.SecretKeyEntry
        return existingKey?.secretKey ?: createKey()
    }

    // you should check if there is any key previously present or not.
    // creating Cipher Key
    private fun createKey(): SecretKey {
        return KeyGenerator.getInstance(ALGORITHM).apply {
            init(
                KeyGenParameterSpec.Builder(
                    ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setKeySize(KEY_SIZE * 8) // key size in bits
                    .setBlockModes(BLOCK_MODE)
                    .setEncryptionPaddings(PADDING)
                    .setUserAuthenticationRequired(false)
                    .setRandomizedEncryptionRequired(true)
                    .build()
            )
        }.generateKey()
    }

    fun encrypt(bytes: ByteArray, outputStream: OutputStream): ByteArray{
//        val encryptedBytes = encryptCipher.doFinal(bytes)
//        outputStream.use {
//            it.write(encryptCipher.iv.size)
//            it.write(encryptCipher.iv)
//            it.write(encryptedBytes.size)
//            it.write(encryptedBytes)
//        }

        val cipher = encryptCipher
        val iv = cipher.iv
        outputStream.use {
            it.write(iv)

            val inputStream = ByteArrayInputStream(bytes)
            val buffer = ByteArray(CHUNK_SIZE)
            while (inputStream.available() > CHUNK_SIZE){
                inputStream.read(buffer)
                val cipherTextChunk = cipher.update(buffer)
                it.write(cipherTextChunk)
            }

            val remainingBytes = inputStream.readBytes()
            val lastChunk = cipher.doFinal(remainingBytes)
            it.write(lastChunk)
            return lastChunk
        }
        //return encryptedBytes
    }

    fun decrypt(inputStream: InputStream): ByteArray {
        return inputStream.use {
            //val ivSize = it.read()
            val iv = ByteArray(KEY_SIZE)
            it.read(iv)
            val outputStream = ByteArrayOutputStream()
            val cipher = getDecryptCipherForIV(iv)

            val buffer = ByteArray(CHUNK_SIZE)
            while (inputStream.available() > CHUNK_SIZE){
                inputStream.read(buffer)
                val cipherTextChunk = cipher.update(buffer)
                outputStream.write(cipherTextChunk)
            }

//            val encryptedBytesSize = it.read()
//            val encryptedBytes = ByteArray(encryptedBytesSize)
//            it.read(encryptedBytes)

            val remainingBytes = inputStream.readBytes()
            val lastChunk = cipher.doFinal(remainingBytes)
            outputStream.write(lastChunk)

            //getDecryptCipherForIV(iv).doFinal(encryptedBytes)
            outputStream.toByteArray()
        }


        /*
        // use these when working with clearText: String

        fun encrypt(clearText: String): String {
            val cipherText =
                Base64.encodeToString(encryptCipher.doFinal(clearText.toByteArray()), Base64.DEFAULT)
            val iv = Base64.encodeToString(encryptCipher.iv, Base64.DEFAULT)

            return "${cipherText}.$iv"
        }
        fun decrypt(cipherText: String): String {
            val array = cipherText.split(".")
            val cipherData = Base64.decode(array.first(), Base64.DEFAULT)
            val iv = Base64.decode(array[1], Base64.DEFAULT)

            val clearText = getDecryptCipherForIv(iv).doFinal(cipherData)

            return String(clearText, 0, clearText.size, Charsets.UTF_8)
        }

        */

    }

    companion object{
        private const val ALGORITHM = KeyProperties.KEY_ALGORITHM_AES
        private const val BLOCK_MODE = KeyProperties.BLOCK_MODE_CBC
        private const val PADDING = KeyProperties.ENCRYPTION_PADDING_PKCS7
        private const val TRANSFORMATION = "$ALGORITHM/$BLOCK_MODE/$PADDING"

        private const val ALIAS = "my_alias"

        // Added After inorder to solve javax.crypto.BadPaddingException
        private const val CHUNK_SIZE = 1024*4 //bytes
        private const val KEY_SIZE = 16 //bytes



    }

}