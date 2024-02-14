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
import java.nio.ByteBuffer
import java.util.concurrent.atomic.AtomicInteger

var NDN_HOST = System.getenv("NDN_HOST") ?: "localhost"
var NDN_PORT = getEnvAsInt("NDN_PORT") ?: 6363
var NDN_ID = getEnvAsInt("NDN_ID")

fun getEnvAsInt(name: String): Int? {
    return try {
        System.getenv(name).toInt();
    } catch (e: Exception) {
        null;
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
        println("Got Discovery request")
        val name = Name("/esp/discovery/$NDN_ID/1")
        val data = Data(name)
        data.metaInfo.freshnessPeriod = 100.0

        face.putData(data)
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
//        println("Link quality for ${interest.name}")
        try {
            val deviceId = interest.name[2].toEscapedString().toLong();
            val timestamp = ByteBuffer.wrap(ByteArray(8, { interest.name[3].value.buf()[it]}).reversedArray()).getLong();
//            println("  $deviceId, $timestamp")

        } catch (e: Exception) {
            println("LinkQuality packet has wrong format.")
        }

    }
}


class LinkQualityInterestHandler : OnData, OnTimeout {
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


fun registerLinkQualityCheckHandler(face: Face, runningCounter: AtomicInteger) {
    val nameObj = Name("/esp/linkqualitycheck")
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


fun sendLinkQualityMessage(face: Face) {
    val name = Name("/esp/linkqualitycheck/$NDN_ID")
    val buffer = ByteBuffer.allocate(8)
    buffer.putLong(System.currentTimeMillis())
    name.append(buffer.array().reversedArray())
    val interest = Interest(name)

    interest.mustBeFresh = true
    interest.interestLifetimeMilliseconds = 1000.0
    face.expressInterest(interest, LinkQualityInterestHandler())
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

    val runningCounter = AtomicInteger(1)
    registerDiscoveryHandler(face, runningCounter)
    registerLinkQualityCheckHandler(face, runningCounter)

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
