package cryptography

import java.awt.Color
import java.awt.image.BufferedImage
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import javax.imageio.ImageIO
import kotlin.experimental.xor
import kotlin.system.exitProcess
import kotlin.text.StringBuilder

fun main() {

    while (true) {
        println("Task (hide, show, exit):")
        val input = readln().lowercase()
        when (input) {
            "exit" -> {
                println("Bye!")
                exitProcess(0)
            }

            "hide" -> {
                println("Input image file:")
                val inputImageFileName = readln()
                println("Output image file:")
                val outputImageFileName = readln().trim()
                val inputFile = File(inputImageFileName)
                val outputFile = File(outputImageFileName)
                if (!inputFile.exists()) {
                    println("Can't read input file!")
                    continue
                }
                var image: BufferedImage
                try {
                    val loadedImage = ImageIO.read(inputFile)
                    image = BufferedImage(loadedImage.width, loadedImage.height, BufferedImage.TYPE_INT_RGB)
                    image.graphics.drawImage(loadedImage, 0, 0, loadedImage.width, loadedImage.height, null)
                    image.graphics.dispose()
                } catch (e: IOException) {
                    println("Error while reading input file.")
                    continue
                }

                println("Message to hide:")
                /* Read the message from input and add 3 bytes to the end of
                * it signifying the end of the message. */
                val inputMessage = readln().encodeToByteArray()

                /* Request a password from the user to encrypt the message with. */
                println("Password:")
                val password = readln()

                // Old approach adding 0 0 3 before XOR'ing message bytes
//                val messageBytes = byteArrayOf(*inputMessage, 0, 0, 3)

                // New approach without adding the 0 0 3 after the message before xor'ing the message bytes
                val messageBytes = byteArrayOf(*inputMessage)

                /* Check if the image is large enough to hold the message. */
                if (image.width * image.height < messageBytes.size * 8) {
                    println("The input image is not large enough to hold this message.")
                    continue
                }

                val encryptedMessageBytes = XorBytesWithPassword(password, messageBytes)
                encryptedMessageBytes.addAll(listOf(0,0,3))

                /* Convert the messages bytes to a list of bits represented as binary. */
                val powersOf2 = arrayOf(1, 2, 4, 8, 16, 32, 64).reversedArray()
                val message8BitStrings = mutableListOf<String>() // The bits of the message.
                for (i in encryptedMessageBytes.indices) {
                    val builder = StringBuilder()
                    for (power in powersOf2) {
                        if (encryptedMessageBytes[i] >= power) {
                            builder.append(1)
                            encryptedMessageBytes[i] = (encryptedMessageBytes[i] - power).toByte()
                        } else builder.append(0)
                    }
                    /* In-case the binary string isn't 8 bits in length, pad the start
                    * with zeroes. */
                    message8BitStrings.add(builder.toString().padStart(8, '0'))
                }

                /* Join the byte bits together as one long string of bits. */
                val messageBits = message8BitStrings.joinToString("")

                var bitIndex = 0
//                for (i in messageBits.indices) {
                    for (y in 0 until image.height) {
                        for (x in 0 until image.width) {
                            if (bitIndex >= messageBits.length) break
                            val messageBit = messageBits[bitIndex].digitToInt()
                            val color = Color(image.getRGB(x, y))
                            image.setRGB(x, y, Color(color.red, color.green, color.blue.and(254).or(messageBit) % 256).rgb)
                            bitIndex++
                        }
                    }
//                }
                /* Save the image. */
                try {
                    ImageIO.write(image, "png", outputFile)
                    println("Message saved in $outputImageFileName image.")
                } catch (e: IOException) {
                    println("Error while writing to output file.")
                    continue
                }
            }

            "show" -> {
                println("Input image file:")
                val imageFileName = readln()
                val byteArrayOutputStream = ByteArrayOutputStream()
                val inputImage: BufferedImage // the image used to reconstruct the message.
                try {
                    inputImage = ImageIO.read(File(imageFileName))
                } catch (e: Exception) {
                    println("Error reading input image.")
                    continue
                }

                println("Password:")
                val password = readln()

                val messageBits = mutableListOf<Int>()
                val width = inputImage.width
                val height = inputImage.height
                for (y in 0 until height) {
                    for (x in 0 until width) {
                        val rgb = inputImage.getRGB(x, y)
                        val color = Color(rgb)
                        val lsb = color.blue and 1 // if this returns 1 then the value of the least significant bit of the blue channel is 1. otherwise its 0.
                        messageBits.add(lsb)
                    }
                }
                val rawBinaryString = messageBits.joinToString("")
                /* Convert the list of integers to a List<String> with the strings being raw binary
                * with the last 3 bytes removed (because they are the terminating bytes). */
//                val bitStrings = rawBinaryString.chunked(8).dropLast(3).map { it.joinToString("") }
                val bitStrings = rawBinaryString.chunked(8)
                /* Used when converting the raw binary strings back to individual bytes. */
                val powersOfTwo = intArrayOf(1, 2, 4, 8, 16, 32, 64, 128).reversedArray()
                val imageBytes = bitStrings.map {
                    /* For each character in the string, convert the character to a digit
                    * and keep count of the index of the character. Traverse each character
                    * and if the digit is 1, multiply the index of the bit with the
                    * value of the corresponding index in the powers array. */
                    var sum = 0
                    it.forEachIndexed { index, char ->
                        /* If the digit is a 1 then add the power corresponding the index of the character. */
                        if (char.digitToInt() == 1) {
                            sum += powersOfTwo[index]
                        }
                    }
                    sum
                }
                /* Convert the bytes to characters, join them into a string and print the result. */
//                val message = messageBytes.map { it.toChar() }.joinToString("").substringBefore("${0.toChar()}${0.toChar()}${3.toChar()}")
                /* Iterate through the images bytes three bytes at a time.
                * When a = 0, b = 0, and c = 3, stop adding bytes to the message bytes list. */
                val messageBytes = mutableListOf<Byte>()
                for (i in imageBytes.indices) {
//                for (i in messageBytes.indices) {
                    val a = imageBytes[i]
//                    val a = messageBytes[i].toInt()
                    val b = if (i + 1 < imageBytes.size) imageBytes[i + 1] else -1
                    val c = if (i + 2 < imageBytes.size) imageBytes[i + 2] else -1
                    if (a == 0 && b == 0 && c == 3) {
                        break
                    } else {
                        messageBytes.add(imageBytes[i].toByte())
                    }
                }
                println("Message:")
//                println(message)
                val messageArray = XorBytesWithPassword(password, messageBytes.toByteArray()).map { Char(it.toInt()) }
                println(messageArray.joinToString(""))
//                println(XorBytesWithPassword(password, messageBytes.toByteArray()).map { it.toInt() } )
//                val xoredBytes = XorBytesWithPassword(password, messageBytes.toByteArray())
//                println("Bytes to chars:")
//                xoredBytes.forEach { byte -> println(Char(byte.toInt())) }
            }

            else -> {
                println("Wrong task: $input")
            }
        }
    }
}

/**
 * Encrypts or decrypts `message` using `password`.
 * This works by XOR'ing each message byte with a corresponding password byte with
 * the same index. If the password is shorter than the message, then indexing of
 * the password restarts from the beginning once it has reached the end of the password.
 *
 * @param password The password as a string of characters.
 * @param message The message as an array of bytes representing characters.
 *
 * @return A list of bytes representing the encrypted or decrypted message.
 */
private fun XorBytesWithPassword(password: String, message: ByteArray): MutableList<Byte> {
    val encryptedMessageBytes = mutableListOf<Byte>()
    val passwordBytes = password.encodeToByteArray()
    var passwordIndex = 0 // the index into the password
    for (index in message.indices) {
        val encryptedByte = message[index] xor passwordBytes[passwordIndex]
        encryptedMessageBytes.add(encryptedByte)
        /* Reset the byte count to 0 when the message index exceeds the password's length. */
        if (passwordIndex >= passwordBytes.size - 1) passwordIndex = 0
        else passwordIndex++
    }
    return encryptedMessageBytes
}