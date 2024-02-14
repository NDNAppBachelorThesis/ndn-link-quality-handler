package de.matthes.ndnLQH

import net.named_data.jndn.*
import net.named_data.jndn.encoding.Tlv0_3WireFormat
import net.named_data.jndn.encoding.WireFormat
import net.named_data.jndn.security.KeyChain
import net.named_data.jndn.security.SecurityException
import net.named_data.jndn.security.identity.IdentityManager
import net.named_data.jndn.security.identity.MemoryIdentityStorage
import net.named_data.jndn.security.identity.MemoryPrivateKeyStorage
import net.named_data.jndn.transport.TcpTransport
import net.named_data.jndn.util.Blob
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger
import kotlin.math.min

var NDN_HOST = System.getenv("NDN_HOST") ?: "localhost"
var NDN_PORT = getEnvAsInt("NDN_PORT") ?: 6363
var NDN_ID = getEnvAsInt("NDN_ID")

// Maps deviceId -> List[received timestamps]
val linkQualityMap = mutableMapOf<Long, LinkQuality>();

fun getEnvAsInt(name: String): Int? {
    return try {
        System.getenv(name).toInt();
    } catch (e: Exception) {
        null;
    }
}


class LinkQuality(val timestamps: MutableList<Long>, var lastUpdateTime: Long) {
    fun calculateLinkQuality(): Float {
        if (timestamps.size < 2) {
            return 0.0f
        }

        val expectedDelay = 1000.0f
        val mn = timestamps.first()
        val mx = timestamps.last()
        val size = timestamps.size
        val averageDelay = (mx - mn) / (size - 1)

        return min(expectedDelay / averageDelay, 1.0f)
    }
}


class DiscoveryHandler : OnInterestCallback {
    override fun onInterest(
        prefix: Name,
        interest: Interest,
        face: Face,
        interestFilterId: Long,
        filter: InterestFilter?
    ) {
        println("Got Discovery request ${interest.name}")
        if (!shouldRespondToDiscovery(interest.name)) {
            println("  -> Already answered. Skipping!")
            return
        }
        val name = Name("/esp/discovery/$NDN_ID/1")
        val data = Data(name)
        data.metaInfo.freshnessPeriod = 100.0

        face.putData(data)
    }

    fun shouldRespondToDiscovery(name: Name): Boolean {

        for (i in 2..<name.size()) {
            val id = ByteBuffer.wrap(ByteArray(8) { name[i].value.buf()[it] }.reversedArray()).getLong()
            if (id.toString() == "$NDN_ID") {
                return false
            }
        }

        return true;
    }

}


class LinkQualityCheckHandler : OnInterestCallback {
    override fun onInterest(
        prefix: Name,
        interest: Interest,
        face: Face,
        interestFilterId: Long,
        filter: InterestFilter?
    ) {
//        println("Link quality for ${interest.name}")
        try {
            val deviceId = interest.name[2].toEscapedString().toLong();
            val timestamp = ByteBuffer.wrap(ByteArray(8) { interest.name[3].value.buf()[it] }.reversedArray()).getLong();

            if (!linkQualityMap.containsKey(deviceId)) {
                linkQualityMap[deviceId] = LinkQuality(mutableListOf(), 0)
            }

            val quality = linkQualityMap[deviceId]!!
            if (quality.timestamps.size > 32) {
                quality.timestamps.removeFirst()
            }
            quality.timestamps.add(timestamp)
            quality.lastUpdateTime = System.currentTimeMillis()

        } catch (e: Exception) {
            println("LinkQuality packet has wrong format.")
        }

    }
}


class LinkQualityHandler : OnInterestCallback {
    override fun onInterest(
        prefix: Name,
        interest: Interest,
        face: Face,
        interestFilterId: Long,
        filter: InterestFilter?
    ) {
        println("Got LinkQuality request: ${interest.name}")

        // Remove outdated entries
        val toRemove = mutableListOf<Long>()
        linkQualityMap.forEach {id, quality ->
            if (System.currentTimeMillis() - quality.lastUpdateTime > 1000 * 60 * 60) {     // 1 hour
                toRemove.add(id)
            }
        }
        toRemove.forEach {
            linkQualityMap.remove(it)
        }

        val buffer = ByteBuffer.allocate(12 * linkQualityMap.size)
        var i = 0

        linkQualityMap.forEach {id, quality ->
            buffer.put(12 * i, longToByteArray(id))
            buffer.put(12 * i + 8, floatToByteArray(quality.calculateLinkQuality()))
            i++
        }

        val data = Data(interest.name)
        data.metaInfo.freshnessPeriod = 1000.0
        data.content = Blob(buffer.array())
        face.putData(data)
    }

    fun longToByteArray(value: Long): ByteArray {
        val buffer = ByteBuffer.allocate(8)
        buffer.putLong(value)

        return buffer.array().reversedArray()
    }

    fun floatToByteArray(value: Float): ByteArray {
        val buffer = ByteBuffer.allocate(4)
        buffer.putFloat(value)

        return buffer.array().reversedArray()
    }

}


class AutoSendLinkQualityHandler : OnData, OnTimeout {
    override fun onData(interest: Interest?, data: Data?) {
        print("Data")
    }

    override fun onTimeout(interest: Interest?) {
        print("Timeout")
    }
}


fun buildTestKeyChain(): KeyChain {
    val identityStorage = MemoryIdentityStorage()
    val privateKeyStorage = MemoryPrivateKeyStorage()
    val identityManager = IdentityManager(identityStorage, privateKeyStorage)
    val keyChain = KeyChain(identityManager)
    try {
        keyChain.getDefaultCertificateName()
    } catch (e: SecurityException) {
        keyChain.createIdentity(Name("/test/identity"))
        keyChain.getIdentityManager().defaultIdentity = Name("/test/identity")
    }
    return keyChain
}


fun registerDiscoveryHandler(face: Face, runningCounter: AtomicInteger) {
    val nameObj = Name("/esp/discovery")
    val handler = DiscoveryHandler()

    face.registerPrefix(
        nameObj,
        handler,
        { name ->
            runningCounter.decrementAndGet()
            throw RuntimeException("Registration failed for name '${name.toUri()}'")
        },
        { prefix, registeredPrefixId ->
            println("Successfully registered '${prefix.toUri()}' with id $registeredPrefixId")
        }
    )
}


fun registerLinkQualityCheckHandler(face: Face, runningCounter: AtomicInteger) {
    val nameObj = Name("/esp/linkqualitycheck")
    val handler = LinkQualityCheckHandler()

    face.registerPrefix(
        nameObj,
        handler,
        { name ->
            runningCounter.decrementAndGet()
            throw RuntimeException("Registration failed for name '${name.toUri()}'")
        },
        { prefix, registeredPrefixId ->
            println("Successfully registered '${prefix.toUri()}' with id $registeredPrefixId")
        }
    )
}


fun registerLinkQualityHandler(face: Face, runningCounter: AtomicInteger) {
    val nameObj = Name("/esp/$NDN_ID/linkquality")
    val handler = LinkQualityHandler()

    face.registerPrefix(
        nameObj,
        handler,
        { name ->
            runningCounter.decrementAndGet()
            throw RuntimeException("Registration failed for name '${name.toUri()}'")
        },
        { prefix, registeredPrefixId ->
            println("Successfully registered '${prefix.toUri()}' with id $registeredPrefixId")
        }
    )
}


fun sendLinkQualityMessage(face: Face) {
    val name = Name("/esp/linkqualitycheck/$NDN_ID")
    val buffer = ByteBuffer.allocate(8)
    buffer.putLong(System.currentTimeMillis())
    name.append(buffer.array().reversedArray())
    val interest = Interest(name)

    interest.mustBeFresh = true
    interest.interestLifetimeMilliseconds = 1000.0
    face.expressInterest(interest, AutoSendLinkQualityHandler())
}


fun main() {
    if (NDN_ID == null) {
        throw RuntimeException("You must configure the NDN_ID environment variable!");
    }

    Interest.setDefaultCanBePrefix(true)
    WireFormat.setDefaultWireFormat(Tlv0_3WireFormat.get())
    val face = Face(TcpTransport(), TcpTransport.ConnectionInfo(NDN_HOST, NDN_PORT));
    val keyChain = buildTestKeyChain();
    keyChain.setFace(face);
    face.setCommandSigningInfo(keyChain, keyChain.defaultCertificateName);

    val runningCounter = AtomicInteger(1)   // Stop when one handler fails
    registerDiscoveryHandler(face, runningCounter)
    registerLinkQualityCheckHandler(face, runningCounter)
    registerLinkQualityHandler(face, runningCounter)

    var lastTime = System.currentTimeMillis();
    while (runningCounter.get() > 0) {
        if (System.currentTimeMillis() - lastTime > 1000) {
            sendLinkQualityMessage(face)
            lastTime = System.currentTimeMillis();
        }

        face.processEvents()
        Thread.sleep(1)   // Prevent 100% CPU load
    }
}
