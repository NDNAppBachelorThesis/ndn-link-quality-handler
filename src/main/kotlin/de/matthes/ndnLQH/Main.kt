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
import java.util.concurrent.atomic.AtomicInteger

var NDN_HOST = System.getenv("NDN_HOST") ?: "localhost"
var NDN_PORT = System.getenv("NDN_PORT") as Int? ?: 6363


class LinkQualityHandler : OnInterestCallback {
    override fun onInterest(
        prefix: Name,
        interest: Interest,
        face: Face,
        interestFilterId: Long,
        filter: InterestFilter?
    ) {
        println("Link quality for ${interest.name}")
        try {
            val deviceId = interest.name[2].toEscapedString().toLong();
            val response = Data(interest.name)
            // DO NOT SET TO 0!!! This will result in the device not receiving any data
            response.metaInfo.freshnessPeriod = 100.0;
            response.content = Blob("Hallo $deviceId")
            face.putData(response);

        } catch (e: Exception) {
            println("LinkQuality packet has wrong format.")
        }

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


fun main() {
    Interest.setDefaultCanBePrefix(true)
    WireFormat.setDefaultWireFormat(Tlv0_3WireFormat.get())
    val face = Face(TcpTransport(), TcpTransport.ConnectionInfo(NDN_HOST, NDN_PORT));
    val keyChain = buildTestKeyChain();
    keyChain.setFace(face);
    face.setCommandSigningInfo(keyChain, keyChain.defaultCertificateName);

    val nameObj = Name("/esp/linkqualityhandler")
    val handler = LinkQualityHandler()

    val runningCounter = AtomicInteger(1)
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

    while (runningCounter.get() > 0) {
        face.processEvents();
        Thread.sleep(10);   // Prevent 100% CPU load
    }
}